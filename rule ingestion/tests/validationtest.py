import pytest
from pydantic import ValidationError

from app.models.rule_models import RuleIngestRequest, ParsedRule, RuleFormatEnum


def test_valid_ingest_request():
    request = RuleIngestRequest(
        repo_url="https://github.com/SigmaHQ/sigma.git",
        branch="main",
        rule_types=[RuleFormatEnum.SIGMA],
    )

    assert request.branch == "main"
    assert request.rule_types == [RuleFormatEnum.SIGMA]


def test_invalid_repo_url():
    with pytest.raises(ValidationError):
        RuleIngestRequest(
            repo_url="not-a-valid-url",
            branch="main",
            rule_types=[RuleFormatEnum.SIGMA],
        )


def test_empty_branch():
    with pytest.raises(ValidationError):
        RuleIngestRequest(
            repo_url="https://github.com/SigmaHQ/sigma.git",
            branch="",
            rule_types=[RuleFormatEnum.SIGMA],
        )


def test_valid_parsed_rule():
    rule = ParsedRule(
        rule_id="RULE-001",
        title="Encoded PowerShell",
        description="Detects encoded PowerShell execution",
        author="SigmaHQ",
        content_hash="a" * 64,
        rule_format=RuleFormatEnum.SIGMA,
        mitre_techniques=["T1059"],
        detection_logic={"selection": {"EventID": 4688}},
        syntax_valid=True,
        validation_errors=[],
    )

    assert rule.rule_id == "RULE-001"
    assert rule.syntax_valid


def test_invalid_hash():
    with pytest.raises(ValidationError):
        ParsedRule(
            rule_id="RULE-001",
            title="Encoded PowerShell",
            content_hash="12345",
            rule_format=RuleFormatEnum.SIGMA,
            detection_logic={},
            syntax_valid=True,
        )


def test_invalid_mitre():
    with pytest.raises(ValidationError):
        ParsedRule(
            rule_id="RULE-001",
            title="Encoded PowerShell",
            content_hash="a" * 64,
            rule_format=RuleFormatEnum.SIGMA,
            mitre_techniques=["INVALID"],
            detection_logic={},
            syntax_valid=True,
        )


def test_invalid_severity():
    with pytest.raises(ValidationError):
        ParsedRule(
            rule_id="RULE-001",
            title="Encoded PowerShell",
            content_hash="a" * 64,
            severity="urgent",
            rule_format=RuleFormatEnum.SIGMA,
            detection_logic={},
            syntax_valid=True,
        )


def test_validation_error_conflict():
    with pytest.raises(ValidationError):
        ParsedRule(
            rule_id="RULE-001",
            title="Encoded PowerShell",
            content_hash="a" * 64,
            rule_format=RuleFormatEnum.SIGMA,
            detection_logic={},
            syntax_valid=True,
            validation_errors=["Missing detection block"],
        )