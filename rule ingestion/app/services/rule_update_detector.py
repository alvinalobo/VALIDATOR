"""
rule_update_detector.py

Monitors Git repositories for new commits and triggers re-ingestion
of detection rules when updates are detected. Implements the rule
change notification system that alerts the Validation Engine.
"""

import hashlib
import logging
import time
import threading
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime

import git

logger = logging.getLogger(__name__)


class RuleUpdateEvent:
    """Represents a detected rule update."""

    def __init__(
        self,
        repo_url: str,
        branch: str,
        commit_hash: str,
        changed_files: List[str],
        timestamp: datetime,
    ):
        self.repo_url = repo_url
        self.branch = branch
        self.commit_hash = commit_hash
        self.changed_files = changed_files
        self.timestamp = timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_url": self.repo_url,
            "branch": self.branch,
            "commit_hash": self.commit_hash,
            "changed_files": self.changed_files,
            "timestamp": self.timestamp.isoformat(),
        }


class RuleUpdateDetector:
    """
    Monitors Git repositories for new commits that affect detection rules.
    When changes are detected, it triggers callbacks for re-ingestion.
    """

    RULE_EXTENSIONS = (".yml", ".yaml", ".kql")

    def __init__(self):
        self._monitored_repos: Dict[str, Dict[str, Any]] = {}
        self._last_known_commits: Dict[str, str] = {}
        self._callbacks: List[Callable[[RuleUpdateEvent], None]] = []
        self._poll_interval: float = 60.0
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None

    def register_callback(
        self, callback: Callable[[RuleUpdateEvent], None]
    ) -> None:
        """Register a callback to be called when rule updates are detected."""
        self._callbacks.append(callback)

    def monitor_repo(
        self,
        repo_url: str,
        branch: str = "main",
        local_path: Optional[str] = None,
    ) -> None:
        """
        Start monitoring a repository for changes.

        Args:
            repo_url: Git repository URL
            branch: Branch to monitor
            local_path: Local path to the cloned repo (optional)
        """
        key = f"{repo_url}:{branch}"

        self._monitored_repos[key] = {
            "repo_url": repo_url,
            "branch": branch,
            "local_path": local_path,
            "registered_at": datetime.utcnow(),
        }

        # Record current commit as baseline
        if local_path:
            try:
                repo = git.Repo(local_path)
                current_commit = repo.head.commit.hexsha
                self._last_known_commits[key] = current_commit
                logger.info(
                    "Monitoring %s branch %s from commit %s",
                    repo_url, branch, current_commit[:8],
                )
            except Exception as exc:
                logger.warning(
                    "Could not read current commit for %s: %s",
                    repo_url, exc,
                )

    def check_for_updates(self, repo_url: str, branch: str = "main") -> Optional[RuleUpdateEvent]:
        """
        Check a specific repo for new commits since last known state.

        Returns a RuleUpdateEvent if changes are detected, None otherwise.
        """
        key = f"{repo_url}:{branch}"

        if key not in self._monitored_repos:
            logger.warning("Repo %s is not being monitored", repo_url)
            return None

        local_path = self._monitored_repos[key].get("local_path")

        if not local_path:
            logger.warning("No local path set for %s", repo_url)
            return None

        try:
            repo = git.Repo(local_path)

            # Fetch latest changes
            try:
                origin = repo.remotes.origin
                origin.fetch()
            except Exception:
                pass

            current_commit = repo.head.commit.hexsha
            last_known = self._last_known_commits.get(key)

            if last_known and current_commit == last_known:
                return None  # No changes

            # Changes detected!
            changed_files = []
            if last_known:
                try:
                    diff = repo.commit(last_known).diff(current_commit)
                    changed_files = [
                        d.b_path for d in diff
                        if d.b_path and d.b_path.endswith(self.RULE_EXTENSIONS)
                    ]
                except Exception:
                    # If diff fails, mark all files as changed
                    changed_files = ["*"]

            # Update last known commit
            self._last_known_commits[key] = current_commit

            event = RuleUpdateEvent(
                repo_url=repo_url,
                branch=branch,
                commit_hash=current_commit,
                changed_files=changed_files,
                timestamp=datetime.utcnow(),
            )

            logger.info(
                "Rule update detected in %s: %s (%d files changed)",
                repo_url, current_commit[:8], len(changed_files),
            )

            return event

        except Exception as exc:
            logger.error(
                "Error checking for updates in %s: %s", repo_url, exc
            )
            return None

    def _notify_callbacks(self, event: RuleUpdateEvent) -> None:
        """Notify all registered callbacks of a rule update."""
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as exc:
                logger.error(
                    "Callback error for rule update event: %s", exc
                )

    def poll_all_repos(self) -> List[RuleUpdateEvent]:
        """
        Check all monitored repos for updates.
        Returns list of events detected.
        """
        events = []

        for key, info in self._monitored_repos.items():
            event = self.check_for_updates(
                info["repo_url"], info["branch"]
            )
            if event:
                events.append(event)
                self._notify_callbacks(event)

        return events

    def start_polling(
        self, interval: float = 60.0, daemon: bool = True
    ) -> None:
        """
        Start background polling thread.

        Args:
            interval: Seconds between checks
            daemon: Run as daemon thread (dies with main process)
        """
        if self._running:
            logger.warning("Polling is already running")
            return

        self._poll_interval = interval
        self._running = True

        def _poll_loop():
            logger.info(
                "Started rule update polling (interval=%ds)", interval
            )
            while self._running:
                try:
                    self.poll_all_repos()
                except Exception as exc:
                    logger.error("Polling error: %s", exc)
                time.sleep(interval)
            logger.info("Stopped rule update polling")

        self._thread = threading.Thread(
            target=_poll_loop, daemon=daemon, name="rule-update-detector"
        )
        self._thread.start()

    def stop_polling(self) -> None:
        """Stop the background polling thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def get_monitored_repos(self) -> List[Dict[str, Any]]:
        """Return list of all monitored repositories."""
        return [
            {
                "repo_url": info["repo_url"],
                "branch": info["branch"],
                "last_known_commit": self._last_known_commits.get(
                    f"{info['repo_url']}:{info['branch']}", "unknown"
                ),
                "registered_at": info["registered_at"].isoformat(),
            }
            for info in self._monitored_repos.values()
        ]


# ============================================================
# NOTIFICATION SYSTEM
# ============================================================

class RuleChangeNotifier:
    """
    Notifies the Validation Engine when a rule has changed
    and existing validations may need to be re-run.
    """

    def __init__(self):
        self._notifications: List[Dict[str, Any]] = []
        self._subscribers: List[Callable] = []

    def notify_rule_changed(
        self,
        rule_id: str,
        event: RuleUpdateEvent,
        reason: str = "Rule content updated in Git repository",
    ) -> Dict[str, Any]:
        """
        Create a notification that a rule has changed.
        """
        notification = {
            "notification_id": hashlib.sha256(
                f"{rule_id}:{event.commit_hash}:{time.time()}".encode()
            ).hexdigest()[:16],
            "rule_id": rule_id,
            "event": event.to_dict(),
            "reason": reason,
            "created_at": datetime.utcnow().isoformat(),
            "requires_rerun": True,
        }

        self._notifications.append(notification)

        # Notify subscribers
        for subscriber in self._subscribers:
            try:
                subscriber(notification)
            except Exception as exc:
                logger.error("Subscriber notification error: %s", exc)

        logger.info(
            "Rule change notification created for %s (commit %s)",
            rule_id, event.commit_hash[:8],
        )

        return notification

    def subscribe(self, callback: Callable) -> None:
        """Subscribe to rule change notifications."""
        self._subscribers.append(callback)

    def get_pending_notifications(
        self, rule_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get pending notifications, optionally filtered by rule_id."""
        if rule_id:
            return [
                n for n in self._notifications
                if n["rule_id"] == rule_id
            ]
        return list(self._notifications)

    def mark_acknowledged(self, notification_id: str) -> bool:
        """Mark a notification as acknowledged."""
        for n in self._notifications:
            if n["notification_id"] == notification_id:
                n["requires_rerun"] = False
                return True
        return False


# ============================================================
# SINGLETON INSTANCES
# ============================================================

rule_update_detector = RuleUpdateDetector()
rule_change_notifier = RuleChangeNotifier()
