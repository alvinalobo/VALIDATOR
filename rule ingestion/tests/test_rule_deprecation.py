import pytest
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_deprecate_rule():
    """Test that a rule can be deprecated via the API."""
    from app.api.rules import INGESTED_RULES
    from app.models.rule_models import ParsedRule, RuleFormatEnum

    rule = ParsedRule(
        rule_id="test-rule-001",
        title="Test Rule",
        description="A test rule",
        content_hash="a" * 64,
        rule_format=RuleFormatEnum.SIGMA,
        detection_logic={"selection": {"EventID": 4688}},
        syntax_valid=True,
    )
    INGESTED_RULES[rule.rule_id] = rule

    # Deprecate the rule
    resp = client.post(f"/api/v2/rules/{rule.rule_id}/deprecate")
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False
    assert "successfully deprecated" in resp.json()["message"]


def test_get_rule():
    """Test fetching a rule by ID."""
    from app.api.rules import INGESTED_RULES
    from app.models.rule_models import ParsedRule, RuleFormatEnum

    rule = ParsedRule(
        rule_id="test-rule-002",
        title="Test Rule 2",
        description="Another test rule",
        content_hash="b" * 64,
        rule_format=RuleFormatEnum.SIGMA,
        detection_logic={"selection": {"EventID": 4688}},
        syntax_valid=True,
    )
    INGESTED_RULES[rule.rule_id] = rule

    resp = client.get(f"/api/v2/rules/{rule.rule_id}")
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == "test-rule-002"


def test_rule_not_found():
    """Test 404 for non-existent rule."""
    resp = client.get("/api/v2/rules/nonexistent-rule-id")
    assert resp.status_code == 404
