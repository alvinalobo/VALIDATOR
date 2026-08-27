from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.api.rules import INGESTED_RULES
from app.models.rule_models import ParsedRule, RuleFormatEnum


client = TestClient(app)


def make_rule(
    rule_id: str,
    title: str,
    *,
    severity: str,
    status: bool = True,
    tags=None,
    techniques=None,
    rule_format=RuleFormatEnum.SIGMA,
    created_at=None,
):
    created_at = created_at or datetime.utcnow()
    return ParsedRule(
        rule_id=rule_id,
        title=title,
        description=f"Detection for {title}",
        content_hash=(rule_id.replace("-", "") + "0" * 64)[:64],
        rule_format=rule_format,
        mitre_techniques=techniques or [],
        detection_logic={"selection": {"EventID": 4688}},
        syntax_valid=True,
        severity=severity,
        tags=tags or [],
        created_at=created_at,
        updated_at=created_at,
        is_active=status,
    )


def setup_rules():
    INGESTED_RULES.clear()
    now = datetime.utcnow()
    rules = [
        make_rule(
            "search-001",
            "PowerShell Download",
            severity="high",
            tags=["powershell", "execution"],
            techniques=["T1059", "T1059.001"],
            created_at=now - timedelta(days=3),
        ),
        make_rule(
            "search-002",
            "Malware Execution",
            severity="critical",
            tags=["malware", "execution"],
            techniques=["T1059"],
            created_at=now - timedelta(days=2),
            rule_format=RuleFormatEnum.KQL,
        ),
        make_rule(
            "search-003",
            "Deprecated PowerShell Rule",
            severity="high",
            tags=["powershell", "deprecated"],
            techniques=["T1059.001"],
            created_at=now - timedelta(days=1),
            status=False,
        ),
    ]
    for rule in rules:
        INGESTED_RULES[rule.rule_id] = rule


def test_search_route_is_registered_and_returns_metadata():
    setup_rules()

    response = client.get("/api/v2/rules/search")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["page_size"] == 20
    assert body["total_pages"] == 1
    assert len(body["items"]) == 3


def test_search_keyword_matches_title_description_and_tags():
    setup_rules()

    response = client.get("/api/v2/rules/search", params={"q": "powershell"})

    assert response.status_code == 200
    ids = {item["rule_id"] for item in response.json()["items"]}
    assert ids == {"search-001", "search-003"}


def test_search_filters_by_status_severity_mitre_and_format():
    setup_rules()

    response = client.get(
        "/api/v2/rules/search",
        params={
            "status": "active",
            "severity": "critical",
            "mitre_technique": "t1059",
            "rule_format": "kql",
        },
    )

    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["rule_id"] for item in items] == ["search-002"]


def test_search_pagination_and_title_sorting():
    setup_rules()

    response = client.get(
        "/api/v2/rules/search",
        params={
            "page": 1,
            "page_size": 2,
            "sort_by": "title",
            "sort_order": "asc",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["total_pages"] == 2
    assert body["page_size"] == 2
    assert [item["title"] for item in body["items"]] == [
        "Deprecated PowerShell Rule",
        "Malware Execution",
    ]


def test_search_invalid_query_parameters_return_400():
    setup_rules()

    for params in (
        {"status": "unknown"},
        {"rule_format": "xml"},
        {"sort_by": "unknown"},
        {"sort_order": "sideways"},
    ):
        response = client.get("/api/v2/rules/search", params=params)
        assert response.status_code == 400


def test_search_page_validation():
    setup_rules()

    response = client.get(
        "/api/v2/rules/search",
        params={"page": 0},
    )

    assert response.status_code == 422
