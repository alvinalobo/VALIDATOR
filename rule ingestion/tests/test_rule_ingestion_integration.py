"""
Week 3 deliverable: integration test for the Rule Ingestion pipeline.

Drives the real `/api/v2/rules/ingest` endpoint against a local fixture
repository holding 10 Sigma rules and 5 KQL queries. No network access and no
vendor sandbox are required — the fixture directory is treated as the
"local test Git repository" the deliverable calls for, which is exactly what
`clone_repo()`'s local-path branch supports.

The tests assert on the observable contract (file discovery, parsing, MITRE
extraction, validation reporting, deprecation status), not on internals.
"""

import os
import sys
from pathlib import Path

import pytest

# Configure python path to project root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from fastapi.testclient import TestClient

from app.main import app
from app.api.rules import INGESTED_RULES

client = TestClient(app)

FIXTURE_REPO = Path(__file__).resolve().parent / "fixtures" / "rule_repo"
SIGMA_DIR = FIXTURE_REPO / "sigma"
KQL_DIR = FIXTURE_REPO / "kql"


@pytest.fixture(autouse=True)
def clean_ingested_rules():
    INGESTED_RULES.clear()
    yield
    INGESTED_RULES.clear()


def _ingest(**overrides):
    payload = {"repo_url": str(FIXTURE_REPO)}
    payload.update(overrides)
    response = client.post("/api/v2/rules/ingest", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


# ----------------------------------------------------------------------
# Fixture repository shape
# ----------------------------------------------------------------------

def test_fixture_repository_has_ten_sigma_and_five_kql_rules():
    """The Week 3 deliverable specifies exactly 10 Sigma rules and 5 KQL queries."""
    sigma_rules = sorted(SIGMA_DIR.glob("*.yml"))
    kql_rules = sorted(KQL_DIR.glob("*.kql"))

    assert len(sigma_rules) == 10, [p.name for p in sigma_rules]
    assert len(kql_rules) == 5, [p.name for p in kql_rules]


# ----------------------------------------------------------------------
# End-to-end ingestion
# ----------------------------------------------------------------------

def test_ingest_parses_every_rule_in_the_fixture_repository():
    rules = _ingest()

    assert len(rules) == 15, f"expected 15 rules, got {len(rules)}"
    assert all(rule["syntax_valid"] for rule in rules), [
        (r["rule_id"], r["validation_errors"]) for r in rules if not r["syntax_valid"]
    ]


def test_ingest_returns_both_rule_formats():
    rules = _ingest()
    formats = {rule["rule_format"] for rule in rules}
    assert formats == {"sigma", "kql"}


def test_kql_rules_are_ingested_with_a_query_string_as_detection_logic():
    """KQL has no YAML structure, so detection_logic is the raw query string."""
    rules = _ingest()
    kql_rules = [r for r in rules if r["rule_format"] == "kql"]

    assert len(kql_rules) == 5
    for rule in kql_rules:
        assert isinstance(rule["detection_logic"], str)
        assert rule["detection_logic"].strip()


def test_sigma_rules_are_ingested_with_structured_detection_logic():
    rules = _ingest()
    sigma_rules = [r for r in rules if r["rule_format"] == "sigma"]

    assert len(sigma_rules) == 10
    for rule in sigma_rules:
        assert isinstance(rule["detection_logic"], dict)
        assert "condition" in rule["detection_logic"]


def test_mitre_techniques_are_extracted_from_sigma_tags():
    rules = _ingest()
    by_title = {rule["title"]: rule for rule in rules}

    encoded = by_title["Suspicious PowerShell Encoded Command Execution"]
    assert "T1059.001" in encoded["mitre_techniques"]

    lsass = by_title["Credential Dumping via LSASS Memory Access"]
    assert "T1003.001" in lsass["mitre_techniques"]

    # Non-technique tags such as 'attack.execution' must not leak through.
    assert "ATTACK.EXECUTION" not in encoded["mitre_techniques"]


def test_mitre_techniques_are_extracted_from_kql_comment_header():
    rules = _ingest()
    by_title = {rule["title"]: rule for rule in rules}

    cradle = by_title["Suspicious PowerShell Download Cradle"]
    assert set(cradle["mitre_techniques"]) == {"T1059.001", "T1105"}


def test_severity_is_read_from_the_level_field():
    rules = _ingest()
    by_title = {rule["title"]: rule for rule in rules}

    assert by_title["Shadow Copy Deletion Indicative of Ransomware"]["severity"] == "critical"
    assert by_title["Persistence via Scheduled Task Creation"]["severity"] == "medium"


def test_deprecated_sigma_rule_is_marked_inactive():
    rules = _ingest()
    by_title = {rule["title"]: rule for rule in rules}

    deprecated = by_title["Deprecated Example Detection Rule"]
    assert deprecated["is_active"] is False

    # Everything else should remain active.
    active = [r for r in rules if r["title"] != "Deprecated Example Detection Rule"]
    assert all(r["is_active"] for r in active)


def test_ingested_rules_are_stored_and_searchable():
    _ingest()

    # 15 rules, but one is deprecated -> 14 active.
    search = client.get("/api/v2/rules/search", params={"status": "active", "paginated": "true"})
    assert search.status_code == 200
    body = search.json()
    assert body["total"] == 14


def test_rule_types_filter_restricts_ingestion_to_sigma_only():
    rules = _ingest(rule_types=["sigma"])

    assert len(rules) == 10
    assert all(rule["rule_format"] == "sigma" for rule in rules)


def test_rule_types_filter_restricts_ingestion_to_kql_only():
    rules = _ingest(rule_types=["kql"])

    assert len(rules) == 5
    assert all(rule["rule_format"] == "kql" for rule in rules)


def test_ingest_rejects_a_nonexistent_local_path_and_a_bad_url():
    for bad in ("/definitely/not/a/real/path", "not-a-valid-url"):
        response = client.post("/api/v2/rules/ingest", json={"repo_url": bad})
        assert response.status_code == 422, f"{bad} should fail validation"


def test_reingesting_identical_content_is_idempotent():
    first = _ingest()
    second = _ingest()

    assert [r["content_hash"] for r in first] == [r["content_hash"] for r in second]
