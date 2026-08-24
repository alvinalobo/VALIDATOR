import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)
# Configure python search path to root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
from services.rule_ingestion.app.main import app
client = TestClient(app)
def test_ingest_retired_rule():
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
    
    # Ingest the rules
    resp = client.post("/api/v2/rules/ingest", json={
        "repo_url": fixtures_dir,
        "branch": "main",
        "rule_types": ["sigma"]
    })
    assert resp.status_code == 200
    rules = resp.json()
    
    # 1. Verify retired_001 rule is parsed with is_active = False because status is 'deprecated'
    retired_rule = next(r for r in rules if r["rule_id"] == "r1234567-89ab-cdef-0123-456789abcdef")
    assert retired_rule["is_active"] is False
    
    # 2. Verify active DET-002 rule is parsed with is_active = True
    active_rule = next(r for r in rules if r["rule_id"] == "b2345678-9abc-def0-1234-56789abcdef0")
    assert active_rule["is_active"] is True
def test_deprecate_active_rule():
    # Make sure rules are ingested first
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
    client.post("/api/v2/rules/ingest", json={
        "repo_url": fixtures_dir,
        "branch": "main",
        "rule_types": ["sigma"]
    })
    
    # 1. Deprecate active rule DET-002
    resp = client.post("/api/v2/rules/b2345678-9abc-def0-1234-56789abcdef0/deprecate")
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False
    assert "successfully deprecated" in resp.json()["message"]
    
    # 2. Verify we can still fetch the deprecated rule directly (Audit retention check)
    get_resp = client.get("/api/v2/rules/b2345678-9abc-def0-1234-56789abcdef0")
    assert get_resp.status_code == 200
    assert get_resp.json()["is_active"] is False
def test_rule_dependencies():
    # 1. Check dependencies for DET-002 (mocked to have active validation runs)
    resp = client.get("/api/v2/rules/b2345678-9abc-def0-1234-56789abcdef0/dependencies")
    assert resp.status_code == 200
    data = resp.json()
    assert data["rule_id"] == "b2345678-9abc-def0-1234-56789abcdef0"
    assert len(data["dependencies"]) == 2
    assert data["dependencies"][0]["run_id"] == "run-001"
    
    # 2. Check dependencies for retired_001 (should be empty list)
    resp_retired = client.get("/api/v2/rules/r1234567-89ab-cdef-0123-456789abcdef/dependencies")
    assert resp_retired.status_code == 200
    data_retired = resp_retired.json()
    assert len(data_retired["dependencies"]) == 0
