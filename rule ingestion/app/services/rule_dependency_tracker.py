import json
import threading
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
 
 
class RuleHasDependentsError(Exception):
    """Raised by check_before_delete()/check_before_edit() when a rule
    still has validation runs depending on it. Carries the full
    dependent list in .dependents so the caller can show exactly what
    would break, not just that something would."""
 
    def __init__(self, rule_id: str, dependents: List["Dependency"]):
        self.rule_id = rule_id
        self.dependents = dependents
        super().__init__(
            f"Rule '{rule_id}' has {len(dependents)} dependent validation run(s); "
            f"cannot delete/edit without breaking reproducibility of past verdicts."
        )
 
 
@dataclass
class Dependency:
    rule_id: str  # content-addressed SHA-256 hash of the rule version
    dependent_type: str  # 'validation_run' | 'action' | 'revalidation_run'
    dependent_id: str
    recorded_at: str  # ISO 8601 timestamp
    metadata: Dict[str, str] = field(default_factory=dict)
 
 
class RuleDependencyTracker:
    """
    Records which dependents (validation runs, re-validation runs, or
    individual actions) used which rule version, and answers "is it
    safe to delete/edit this rule" before someone does it.
    """
 
    def __init__(self, storage_path: Optional[Path] = None):
        self._storage_path = storage_path
        # rule_id -> list of Dependency
        self._dependencies: Dict[str, List[Dependency]] = {}
        self._lock = threading.Lock()
        if storage_path and storage_path.exists():
            self._load()
 
    def record_usage(
        self,
        rule_id: str,
        dependent_type: str,
        dependent_id: str,
        metadata: Optional[Dict[str, str]] = None,
    ) -> None:
        """Record that `dependent_id` (a validation run, re-validation
        run, or action) used rule `rule_id`. Call this every time the
        Validation Engine actually executes a rule against evidence —
        not just at ingestion time, since ingestion doesn't yet know
        which validation runs will use the rule."""
        dep = Dependency(
            rule_id=rule_id,
            dependent_type=dependent_type,
            dependent_id=dependent_id,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )
        with self._lock:
            self._dependencies.setdefault(rule_id, []).append(dep)
            self._save()
 
    def get_dependents(self, rule_id: str) -> List[Dependency]:
        """Return every recorded dependent of `rule_id`, oldest first."""
        return list(self._dependencies.get(rule_id, []))
 
    def has_dependents(self, rule_id: str) -> bool:
        return len(self._dependencies.get(rule_id, [])) > 0
 
    def check_before_delete(self, rule_id: str) -> None:
        """Raises RuleHasDependentsError if deleting rule_id would strand
        any validation run's audit trail. Returns None (silently) if safe."""
        dependents = self.get_dependents(rule_id)
        if dependents:
            raise RuleHasDependentsError(rule_id, dependents)
 
    def check_before_edit(self, rule_id: str) -> None:
        """Same check as check_before_delete — included as a separate
        name for call-site clarity, since 'editing' a content-addressed
        rule really means 'retiring this hash in favor of a new one',
        which carries the same reproducibility risk as deleting it."""
        self.check_before_delete(rule_id)
 
    def dependency_report(self, rule_id: str) -> str:
        """Human-readable summary for a confirmation prompt/UI, e.g.
        before a detection engineer clicks 'delete' on a rule."""
        dependents = self.get_dependents(rule_id)
        if not dependents:
            return f"Rule '{rule_id}' has no recorded dependents — safe to delete/edit."
 
        by_type: Dict[str, int] = {}
        for dep in dependents:
            by_type[dep.dependent_type] = by_type.get(dep.dependent_type, 0) + 1
 
        lines = [f"Rule '{rule_id}' has {len(dependents)} dependent(s):"]
        for dep_type, count in sorted(by_type.items()):
            lines.append(f"  - {count} {dep_type}(s)")
        lines.append("Deleting/editing this rule will strand these dependents'")
        lines.append("ability to reproduce their original verdict.")
        return "\n".join(lines)
 
    # --- persistence ---
 
    def _save(self) -> None:
        if not self._storage_path:
            return
        serializable = {
            rule_id: [asdict(dep) for dep in deps]
            for rule_id, deps in self._dependencies.items()
        }
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._storage_path.write_text(json.dumps(serializable, indent=2))
 
    def _load(self) -> None:
        raw = json.loads(self._storage_path.read_text())
        self._dependencies = {
            rule_id: [Dependency(**dep) for dep in deps]
            for rule_id, deps in raw.items()
        }
