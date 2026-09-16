"""
rule_versioning.py

Single responsibility: maintain the full version history of every detection
rule, keyed by content-addressed SHA-256 hash.

Why content-addressed rather than a plain incrementing counter: a verdict
produced yesterday must stay reproducible tomorrow. If a rule is edited we
cannot mutate the old record in place — we must keep the superseded hash
addressable forever, because past validation runs reference it by hash, not
by "the current version of rule X".

Semantics
---------
* Re-ingesting identical content is a no-op (same hash -> same version).
* Changed content creates a NEW version and marks the previous one
  superseded (`is_latest=False`). The old version is never deleted.
* Deprecating a rule does not delete history either; it flips `status` to
  "deprecated" and leaves every version retrievable so dependents can still
  reproduce the verdicts they produced.

Storage is in-process by default (matching the rest of the service), with an
optional JSON file backing store so history survives a restart.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class RuleVersioningError(Exception):
    """Raised on an invalid versioning transition (e.g. unknown rule)."""


@dataclass
class RuleVersion:
    """A single immutable snapshot of a rule, addressed by content hash."""

    rule_id: str
    version: int
    content_hash: str
    title: str
    rule_format: str
    status: str = "active"          # 'active' | 'deprecated'
    is_latest: bool = True
    parent_content_hash: Optional[str] = None
    change_log: Optional[str] = None
    recorded_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class RuleVersioningService:
    """
    Tracks every version of every rule and answers the two questions the rest
    of the platform needs:

        * "has this rule's content changed?"  -> is_changed()
        * "give me the exact version that produced this verdict" -> get_version()
    """

    def __init__(self, storage_path: Optional[Path] = None):
        self._storage_path = storage_path
        # rule_id -> list[RuleVersion], oldest first
        self._history: Dict[str, List[RuleVersion]] = {}
        # content_hash -> RuleVersion (global lookup, hashes are unique)
        self._by_hash: Dict[str, RuleVersion] = {}
        self._lock = threading.RLock()
        if storage_path and storage_path.exists():
            self._load()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_version(
        self,
        rule_id: str,
        content_hash: str,
        title: str,
        rule_format: str,
        change_log: Optional[str] = None,
    ) -> RuleVersion:
        """
        Record a rule at `content_hash`, creating a new version only when the
        content has actually changed.

        Returns the RuleVersion representing that content (either a freshly
        created one or the existing record when the content is unchanged).
        """
        if not rule_id or not content_hash:
            raise RuleVersioningError(
                "rule_id and content_hash are required to record a version"
            )

        with self._lock:
            existing = self._by_hash.get(content_hash)
            if existing is not None:
                # Identical content re-ingested: idempotent, no new version.
                return existing

            history = self._history.setdefault(rule_id, [])
            parent_hash = history[-1].content_hash if history else None

            # Supersede whatever is currently latest for this rule.
            for previous in history:
                previous.is_latest = False

            version = RuleVersion(
                rule_id=rule_id,
                version=len(history) + 1,
                content_hash=content_hash,
                title=title,
                rule_format=rule_format,
                status="active",
                is_latest=True,
                parent_content_hash=parent_hash,
                change_log=change_log,
            )
            history.append(version)
            self._by_hash[content_hash] = version
            self._save()
            return version

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_changed(self, rule_id: str, content_hash: str) -> bool:
        """True when this exact content has never been recorded for this rule."""
        with self._lock:
            return content_hash not in self._by_hash

    def get_history(self, rule_id: str) -> List[RuleVersion]:
        """Every recorded version of `rule_id`, oldest first."""
        with self._lock:
            return list(self._history.get(rule_id, []))

    def get_latest(self, rule_id: str) -> Optional[RuleVersion]:
        with self._lock:
            history = self._history.get(rule_id)
            return history[-1] if history else None

    def get_version(self, content_hash: str) -> Optional[RuleVersion]:
        """Resolve a content hash back to the exact version that produced it."""
        with self._lock:
            return self._by_hash.get(content_hash)

    def get_version_number(self, rule_id: str, version: int) -> Optional[RuleVersion]:
        with self._lock:
            for record in self._history.get(rule_id, []):
                if record.version == version:
                    return record
        return None

    def latest_content_hash(self, rule_id: str) -> Optional[str]:
        latest = self.get_latest(rule_id)
        return latest.content_hash if latest else None

    def all_rule_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._history.keys())

    def history_summary(self, rule_id: str) -> Dict[str, object]:
        """Compact payload for the API: current state + change count."""
        history = self.get_history(rule_id)
        if not history:
            return {
                "rule_id": rule_id,
                "version_count": 0,
                "current_version": None,
                "current_content_hash": None,
                "status": None,
                "versions": [],
            }
        latest = history[-1]
        return {
            "rule_id": rule_id,
            "version_count": len(history),
            "current_version": latest.version,
            "current_content_hash": latest.content_hash,
            "status": latest.status,
            "versions": [asdict(v) for v in history],
        }

    # ------------------------------------------------------------------
    # Retirement
    # ------------------------------------------------------------------

    def deprecate(self, rule_id: str, reason: Optional[str] = None) -> RuleVersion:
        """
        Retire a rule *without* breaking reproducibility.

        Every historical version stays addressable by hash; only the rule's
        status changes, so a past verdict can still be explained.
        """
        with self._lock:
            history = self._history.get(rule_id)
            if not history:
                raise RuleVersioningError(f"No version history for rule '{rule_id}'")

            latest = history[-1]
            latest.status = "deprecated"
            if reason:
                latest.change_log = reason
            self._save()
            return latest

    def restore(self, rule_id: str) -> RuleVersion:
        """Reverse a deprecation (a retired rule may be reinstated)."""
        with self._lock:
            history = self._history.get(rule_id)
            if not history:
                raise RuleVersioningError(f"No version history for rule '{rule_id}'")
            latest = history[-1]
            latest.status = "active"
            self._save()
            return latest

    def is_deprecated(self, rule_id: str) -> bool:
        latest = self.get_latest(rule_id)
        return bool(latest and latest.status == "deprecated")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        if not self._storage_path:
            return
        payload = {
            rule_id: [asdict(v) for v in versions]
            for rule_id, versions in self._history.items()
        }
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._storage_path.write_text(json.dumps(payload, indent=2))

    def _load(self) -> None:
        raw = json.loads(self._storage_path.read_text())
        for rule_id, versions in raw.items():
            loaded = [RuleVersion(**v) for v in versions]
            self._history[rule_id] = loaded
            for record in loaded:
                self._by_hash[record.content_hash] = record


# Process-wide default instance used by the API layer. Tests construct their
# own isolated instances rather than mutating this one.
rule_versioning_service = RuleVersioningService()
