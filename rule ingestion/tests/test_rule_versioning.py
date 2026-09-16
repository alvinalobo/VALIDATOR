"""
Week 7 deliverables: rule versioning, the deprecation workflow, and the rule
dependency tracker.

Covers the content-addressed version store directly, plus the API surface that
exposes it (version history, dependency recording, retirement impact).

Note on hashes: content hashes are globally unique (the DB migration enforces
`UniqueConstraint("content_hash")`), so every rule under test uses its own
distinct hash rather than sharing constants.
"""

import os
import sys

import pytest

# Configure python path to project root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from fastapi.testclient import TestClient

from app.main import app
from app.api.rules import INGESTED_RULES
from app.models.rule_models import ParsedRule, RuleFormatEnum
from app.services.rule_dependency_tracker import (
    RuleDependencyTracker,
    RuleHasDependentsError,
)
from app.services.rule_versioning import (
    RuleVersioningService,
    RuleVersioningError,
    rule_versioning_service,
)

client = TestClient(app)


def h(char: str) -> str:
    """Build a valid 64-character SHA-256-shaped hex digest."""
    return char * 64


@pytest.fixture
def versioning():
    """A fresh, isolated version store per test."""
    return RuleVersioningService()


@pytest.fixture(autouse=True)
def clean_state():
    INGESTED_RULES.clear()
    yield
    INGESTED_RULES.clear()


def _make_rule(rule_id: str, content_hash: str, title: str = "Test Rule") -> ParsedRule:
    return ParsedRule(
        rule_id=rule_id,
        title=title,
        content_hash=content_hash,
        rule_format=RuleFormatEnum.SIGMA,
        detection_logic={"selection": {"EventID": 4688}, "condition": "selection"},
        syntax_valid=True,
    )


# ----------------------------------------------------------------------
# Version store
# ----------------------------------------------------------------------

def test_first_version_is_number_one_and_latest(versioning):
    record = versioning.record_version("r-1", h("a"), "Rule One", "sigma")

    assert record.version == 1
    assert record.is_latest is True
    assert record.parent_content_hash is None
    assert record.status == "active"


def test_identical_content_is_idempotent(versioning):
    first = versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    second = versioning.record_version("r-1", h("a"), "Rule One", "sigma")

    assert first is second
    assert len(versioning.get_history("r-1")) == 1


def test_changed_content_creates_a_new_version_and_supersedes_the_old(versioning):
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    second = versioning.record_version("r-1", h("b"), "Rule One v2", "sigma")

    assert second.version == 2
    assert second.parent_content_hash == h("a")

    history = versioning.get_history("r-1")
    assert len(history) == 2
    # Exactly one revision is current.
    assert [v.is_latest for v in history] == [False, True]
    assert versioning.latest_content_hash("r-1") == h("b")


def test_superseded_versions_stay_addressable_by_hash(versioning):
    """The point of content-addressing: an old verdict stays reproducible."""
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    versioning.record_version("r-1", h("b"), "Rule One v2", "sigma")

    original = versioning.get_version(h("a"))
    assert original is not None
    assert original.version == 1
    assert original.content_hash == h("a")


def test_is_changed_detects_new_content(versioning):
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")

    assert versioning.is_changed("r-1", h("a")) is False
    assert versioning.is_changed("r-1", h("b")) is True


def test_version_lookup_by_number(versioning):
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    versioning.record_version("r-1", h("b"), "Rule One v2", "sigma")

    assert versioning.get_version_number("r-1", 1).content_hash == h("a")
    assert versioning.get_version_number("r-1", 2).content_hash == h("b")
    assert versioning.get_version_number("r-1", 99) is None


def test_independent_rules_version_separately(versioning):
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    versioning.record_version("r-2", h("b"), "Rule Two", "kql")
    versioning.record_version("r-1", h("c"), "Rule One v2", "sigma")

    assert [v.version for v in versioning.get_history("r-1")] == [1, 2]
    assert [v.version for v in versioning.get_history("r-2")] == [1]


def test_deprecate_keeps_full_history(versioning):
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    versioning.record_version("r-1", h("b"), "Rule One v2", "sigma")

    versioning.deprecate("r-1", reason="superseded by r-9")

    assert versioning.is_deprecated("r-1") is True
    # Retirement must not discard history - both hashes remain resolvable.
    assert len(versioning.get_history("r-1")) == 2
    assert versioning.get_version(h("a")) is not None
    assert versioning.get_version(h("b")) is not None


def test_restore_reverses_deprecation(versioning):
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    versioning.deprecate("r-1")
    versioning.restore("r-1")

    assert versioning.is_deprecated("r-1") is False


def test_deprecating_an_unknown_rule_raises(versioning):
    with pytest.raises(RuleVersioningError):
        versioning.deprecate("never-seen")


def test_recording_requires_rule_id_and_hash(versioning):
    with pytest.raises(RuleVersioningError):
        versioning.record_version("", h("a"), "t", "sigma")
    with pytest.raises(RuleVersioningError):
        versioning.record_version("r-1", "", "t", "sigma")


def test_history_summary_reports_current_state(versioning):
    versioning.record_version("r-1", h("a"), "Rule One", "sigma")
    versioning.record_version("r-1", h("b"), "Rule One v2", "sigma")

    summary = versioning.history_summary("r-1")
    assert summary["version_count"] == 2
    assert summary["current_version"] == 2
    assert summary["current_content_hash"] == h("b")
    assert summary["status"] == "active"
    assert len(summary["versions"]) == 2


def test_history_summary_for_unknown_rule_is_empty(versioning):
    summary = versioning.history_summary("nope")
    assert summary["version_count"] == 0
    assert summary["versions"] == []


# ----------------------------------------------------------------------
# Dependency tracker
# ----------------------------------------------------------------------

def test_recorded_dependency_blocks_deletion():
    tracker = RuleDependencyTracker()
    tracker.record_usage("r-1", "validation_run", "run-001")

    assert tracker.has_dependents("r-1") is True
    assert len(tracker.get_dependents("r-1")) == 1

    with pytest.raises(RuleHasDependentsError) as exc_info:
        tracker.check_before_delete("r-1")

    assert exc_info.value.rule_id == "r-1"
    assert len(exc_info.value.dependents) == 1


def test_rule_without_dependents_is_safe_to_delete():
    tracker = RuleDependencyTracker()
    tracker.check_before_delete("untouched")  # must not raise

    assert tracker.has_dependents("untouched") is False
    assert "safe to delete" in tracker.dependency_report("untouched")


def test_dependency_report_groups_by_type():
    tracker = RuleDependencyTracker()
    tracker.record_usage("r-1", "validation_run", "run-001")
    tracker.record_usage("r-1", "validation_run", "run-002")
    tracker.record_usage("r-1", "revalidation_run", "rerun-001")

    report = tracker.dependency_report("r-1")
    assert "3 dependent(s)" in report
    assert "2 validation_run(s)" in report
    assert "1 revalidation_run(s)" in report


def test_dependency_tracker_persists_across_instances(tmp_path):
    storage = tmp_path / "deps.json"
    first = RuleDependencyTracker(storage_path=storage)
    first.record_usage("r-1", "validation_run", "run-001")

    reloaded = RuleDependencyTracker(storage_path=storage)
    assert reloaded.get_dependents("r-1")[0].dependent_id == "run-001"


# ----------------------------------------------------------------------
# API surface
# ----------------------------------------------------------------------

def test_deprecating_via_api_records_version_history():
    INGESTED_RULES["api-rule-1"] = _make_rule("api-rule-1", h("1"), "API Rule")

    response = client.post("/api/v2/rules/api-rule-1/deprecate")
    assert response.status_code == 200
    body = response.json()

    assert body["is_active"] is False
    assert body["dependent_count"] == 0
    assert "successfully deprecated" in body["message"]

    versions = client.get("/api/v2/rules/api-rule-1/versions")
    assert versions.status_code == 200
    assert versions.json()["version_count"] == 1
    assert versions.json()["status"] == "deprecated"


def test_version_history_endpoint_404s_for_unknown_rule():
    response = client.get("/api/v2/rules/no-such-rule/versions")
    assert response.status_code == 404


def test_dependency_endpoint_replaces_the_old_mock_data():
    """The endpoint previously returned hardcoded fake runs; it must now be real."""
    INGESTED_RULES["api-rule-2"] = _make_rule("api-rule-2", h("2"), "API Rule 2")

    before = client.get("/api/v2/rules/api-rule-2/dependencies").json()
    assert before["dependent_count"] == 0
    assert before["safe_to_delete"] is True
    assert before["dependencies"] == []

    recorded = client.post(
        "/api/v2/rules/api-rule-2/dependencies",
        json={
            "dependent_type": "validation_run",
            "dependent_id": "run-123",
            "metadata": {"action_id": "act-1"},
        },
    )
    assert recorded.status_code == 201

    after = client.get("/api/v2/rules/api-rule-2/dependencies").json()
    assert after["dependent_count"] == 1
    assert after["safe_to_delete"] is False
    assert after["dependencies"][0]["dependent_id"] == "run-123"


def test_dependency_endpoint_rejects_an_unknown_dependent_type():
    INGESTED_RULES["api-rule-3"] = _make_rule("api-rule-3", h("3"), "API Rule 3")

    response = client.post(
        "/api/v2/rules/api-rule-3/dependencies",
        json={"dependent_type": "nonsense", "dependent_id": "x"},
    )
    assert response.status_code == 400


def test_retirement_impact_reports_dependents():
    INGESTED_RULES["api-rule-4"] = _make_rule("api-rule-4", h("4"), "API Rule 4")
    client.post(
        "/api/v2/rules/api-rule-4/dependencies",
        json={"dependent_type": "action", "dependent_id": "act-9"},
    )

    response = client.get("/api/v2/rules/api-rule-4/impact")
    assert response.status_code == 200
    body = response.json()

    assert body["safe_to_delete"] is False
    assert body["safe_to_edit"] is False
    assert body["dependent_count"] == 1


def test_restore_endpoint_reinstates_a_deprecated_rule():
    INGESTED_RULES["api-rule-5"] = _make_rule("api-rule-5", h("5"), "API Rule 5")

    client.post("/api/v2/rules/api-rule-5/deprecate")
    restored = client.post("/api/v2/rules/api-rule-5/restore")

    assert restored.status_code == 200
    assert restored.json()["is_active"] is True
    assert INGESTED_RULES["api-rule-5"].is_active is True


def test_specific_version_endpoint_resolves_each_revision():
    h1, h2 = h("6"), h("7")
    INGESTED_RULES["api-rule-6"] = _make_rule("api-rule-6", h1, "Rule v1")
    rule_versioning_service.record_version("api-rule-6", h1, "Rule v1", "sigma")
    rule_versioning_service.record_version("api-rule-6", h2, "Rule v2", "sigma")

    v1 = client.get("/api/v2/rules/api-rule-6/versions/1")
    v2 = client.get("/api/v2/rules/api-rule-6/versions/2")

    assert v1.status_code == 200
    assert v1.json()["content_hash"] == h1
    assert v2.status_code == 200
    assert v2.json()["content_hash"] == h2
    assert v2.json()["parent_content_hash"] == h1


def test_specific_version_endpoint_404s_for_a_missing_revision():
    INGESTED_RULES["api-rule-7"] = _make_rule("api-rule-7", h("8"), "Rule")
    rule_versioning_service.record_version("api-rule-7", h("8"), "Rule", "sigma")

    response = client.get("/api/v2/rules/api-rule-7/versions/99")
    assert response.status_code == 404
