import os
import sys
import pytest
from fastapi.testclient import TestClient

# Configure python search path to root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app.main import app
from app.api.rules import INGESTED_RULES
from app.models.rule_models import ParsedRule, RuleFormatEnum

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    INGESTED_RULES.clear()

@pytest.fixture
def populate_rules():
    # 1. Active Sigma Rule, Critical Severity, Technique T1486, tag: attack.impact
    rule1 = ParsedRule(
        rule_id="rule-sigma-01",
        title="Sigma File Encryption",
        description="Detects ransomware encrypting files",
        author="CyArt Tech",
        content_hash="a" * 64,
        rule_format=RuleFormatEnum.SIGMA,
        mitre_techniques=["T1486"],
        detection_logic={"selection": {"CommandLine|contains": "vssadmin"}},
        syntax_valid=True,
        validation_errors=[],
        severity="critical",
        tags=["attack.impact", "ransomware"],
        is_active=True
    )
    # 2. Inactive Sigma Rule, Low Severity, Technique T1059.001, tag: attack.execution
    rule2 = ParsedRule(
        rule_id="rule-sigma-02",
        title="Sigma Powershell",
        description="Deprecated PowerShell check",
        author="CyArt Tech",
        content_hash="b" * 64,
        rule_format=RuleFormatEnum.SIGMA,
        mitre_techniques=["T1059.001"],
        detection_logic={"selection": {"CommandLine|contains": "powershell"}},
        syntax_valid=True,
        validation_errors=[],
        severity="low",
        tags=["attack.execution"],
        is_active=False
    )
    # 3. Active KQL Rule, High Severity, Technique T1059, tag: attack.execution
    rule3 = ParsedRule(
        rule_id="rule-kql-01",
        title="KQL Command Line check",
        description="KQL technique mapping check",
        author="CyArt Tech",
        content_hash="c" * 64,
        rule_format=RuleFormatEnum.KQL,
        mitre_techniques=["T1059"],
        detection_logic={"query": "DeviceProcessEvents | where ProcessCommandLine contains 'whoami'"},
        syntax_valid=True,
        validation_errors=[],
        severity="high",
        tags=["attack.execution"],
        is_active=True
    )
    INGESTED_RULES["rule-sigma-01"] = rule1
    INGESTED_RULES["rule-sigma-02"] = rule2
    INGESTED_RULES["rule-kql-01"] = rule3

def test_filter_by_format(populate_rules):
    # Filter by Sigma
    resp = client.get("/api/v2/rules/search?rule_format=sigma")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 2
    assert all(r["rule_format"] == "sigma" for r in rules)

    # Filter by KQL
    resp_kql = client.get("/api/v2/rules/search?rule_format=kql")
    assert resp_kql.status_code == 200
    rules_kql = resp_kql.json()
    assert len(rules_kql) == 1
    assert rules_kql[0]["rule_id"] == "rule-kql-01"

def test_filter_by_severity(populate_rules):
    # Filter by critical
    resp = client.get("/api/v2/rules/search?severity=critical")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 1
    assert rules[0]["rule_id"] == "rule-sigma-01"

    # Filter by low
    resp_low = client.get("/api/v2/rules/search?severity=low")
    assert resp_low.status_code == 200
    rules_low = resp_low.json()
    assert len(rules_low) == 1
    assert rules_low[0]["rule_id"] == "rule-sigma-02"

def test_filter_by_mitre_technique(populate_rules):
    # Filter by T1059
    resp = client.get("/api/v2/rules/search?mitre_technique=T1059")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 1
    assert rules[0]["rule_id"] == "rule-kql-01"

    # Filter by T1486
    resp_t1486 = client.get("/api/v2/rules/search?mitre_technique=T1486")
    assert resp_t1486.status_code == 200
    rules_t1486 = resp_t1486.json()
    assert len(rules_t1486) == 1
    assert rules_t1486[0]["rule_id"] == "rule-sigma-01"

def test_filter_by_tag(populate_rules):
    # Filter by tag using query search 'q'
    resp = client.get("/api/v2/rules/search?q=attack.execution")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 2
    rule_ids = [r["rule_id"] for r in rules]
    assert "rule-sigma-02" in rule_ids
    assert "rule-kql-01" in rule_ids

def test_filter_by_status(populate_rules):
    # Filter by status = active
    resp = client.get("/api/v2/rules/search?status=active")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 2
    assert all(r["is_active"] is True for r in rules)

    # Filter by status = deprecated
    resp_inactive = client.get("/api/v2/rules/search?status=deprecated")
    assert resp_inactive.status_code == 200
    rules_inactive = resp_inactive.json()
    assert len(rules_inactive) == 1
    assert rules_inactive[0]["rule_id"] == "rule-sigma-02"

def test_filter_combined(populate_rules):
    # Sigma, High Severity (should yield nothing)
    resp = client.get("/api/v2/rules/search?rule_format=sigma&severity=high")
    assert resp.status_code == 200
    assert len(resp.json()) == 0

    # Sigma, Critical Severity, status=active
    resp_match = client.get("/api/v2/rules/search?rule_format=sigma&severity=critical&status=active")
    assert resp_match.status_code == 200
    rules = resp_match.json()
    assert len(rules) == 1
    assert rules[0]["rule_id"] == "rule-sigma-01"
