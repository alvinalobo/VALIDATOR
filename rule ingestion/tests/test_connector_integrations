import os
import sys
import pytest
import httpx
from typing import Dict, Any

# Configure python search path to root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from services.connector_framework.app.base_connector import ConnectorConfig, ConnectorRegistry
import services.connector_framework.app.connectors.splunk_connector
import services.connector_framework.app.connectors.sentinel_connector
import services.connector_framework.app.connectors.elastic_connector
import services.connector_framework.app.connectors.qradar_connector
import services.connector_framework.app.connectors.crowdstrike_connector

# Mock HTTP client responses representing sandbox endpoints
class MockResponse:
    def __init__(self, status_code: int, json_data: Any):
        self.status_code = status_code
        self._json_data = json_data

    def json(self) -> Any:
        return self._json_data

def mock_send(self_client, request: httpx.Request, *args, **kwargs) -> MockResponse:
    url_str = str(request.url)
    
    # 1. Splunk Mock Sandbox Endpoints
    if "/services/search/jobs" in url_str:
        if url_str.endswith("/results?output_mode=json"):
            return MockResponse(200, {"results": [{"host": "WORKSTATION-01", "CommandLine": "vssadmin.exe -encrypt"}]})
        elif "splunk-test-sid-123" in url_str:
            return MockResponse(200, {"entry": [{"content": {"dispatchState": "DONE"}}]})
        elif "/services/search/jobs" in url_str:
            return MockResponse(201, {"sid": "splunk-test-sid-123"})
    elif "/services/authentication/current-context" in url_str:
        return MockResponse(200, {})

    # 2. Microsoft Sentinel Mock Sandbox Endpoints
    elif "login.microsoftonline.com" in url_str:
        return MockResponse(200, {"access_token": "sentinel-mock-access-token"})
    elif "/v1/workspaces/workspace-id-123/query" in url_str:
        return MockResponse(200, {
            "tables": [
                {
                    "name": "PrimaryTable",
                    "columns": [{"name": "Computer"}, {"name": "ProcessCommandLine"}],
                    "rows": [["WORKSTATION-01", "msiexec.exe /i -install"]]
                }
            ]
        })

    # 3. Elastic Mock Sandbox Endpoints
    elif url_str.endswith("/_eql/search") or url_str.endswith("/_search"):
        return MockResponse(200, {
            "hits": {
                "events": [{"_source": {"process": {"command_line": "vssadmin.exe -encrypt"}}}],
                "hits": [{"_source": {"process": {"command_line": "vssadmin.exe -encrypt"}}}]
            }
        })
    elif url_str.endswith(":9200/"):
        return MockResponse(200, {})

    # 4. IBM QRadar Mock Sandbox Endpoints
    elif "/api/ariel/searches" in url_str:
        if "qradar-test-sid-456/results" in url_str:
            return MockResponse(200, {"events": [{"sourceip": "192.168.1.50", "payload": "modbus"}]})
        elif "qradar-test-sid-456" in url_str:
            return MockResponse(200, {"status": "COMPLETED"})
        else:
            return MockResponse(201, {"search_id": "qradar-test-sid-456"})
    elif "/api/ariel/databases" in url_str:
        return MockResponse(200, {})

    # 5. CrowdStrike Mock Sandbox Endpoints
    elif "/api/v1/status" in url_str:
        return MockResponse(200, {})
    elif "/api/v1/repositories/query" in url_str:
        return MockResponse(200, [{"CommandLine": "msiexec.exe"}])

    return MockResponse(404, {"error": "Endpoint not simulated"})

@pytest.fixture(autouse=True)
def mock_httpx_client(monkeypatch):
    """
    Automatically mock httpx.Client.send to redirect all queries to
    our sandbox simulated responses.
    """
    monkeypatch.setattr(httpx.Client, "send", mock_send)

def test_splunk_integration():
    config = ConnectorConfig(
        connector_id="splunk-es-prod",
        vendor="splunk",
        product="splunk_enterprise",
        credentials={"host": "https://splunk-sandbox.internal", "port": 8089, "token": "testtoken", "mock": False}
    )
    connector = ConnectorRegistry.get("splunk")(config)
    assert connector.validate_connection() is True
    
    results = connector.query("index=windows CommandLine=*")
    assert len(results) == 1
    assert results[0]["host"] == "WORKSTATION-01"

def test_sentinel_integration():
    config = ConnectorConfig(
        connector_id="sentinel-la-prod",
        vendor="sentinel",
        product="azure_sentinel",
        credentials={
            "tenant_id": "tenant-123",
            "client_id": "client-123",
            "client_secret": "secret-123",
            "workspace_id": "workspace-id-123",
            "mock": False
        }
    )
    connector = ConnectorRegistry.get("sentinel")(config)
    assert connector.validate_connection() is True
    
    results = connector.query("DeviceProcessEvents | limit 1")
    assert len(results) == 1
    assert results[0]["Computer"] == "WORKSTATION-01"
    assert "msiexec.exe" in results[0]["ProcessCommandLine"]

def test_elastic_integration():
    config = ConnectorConfig(
        connector_id="elastic-sec-prod",
        vendor="elastic",
        product="elastic_security",
        credentials={"host": "https://elastic-sandbox.internal", "port": 9200, "api_key": "key123", "mock": False}
    )
    connector = ConnectorRegistry.get("elastic")(config)
    assert connector.validate_connection() is True
    
    results = connector.query("process.name: *")
    assert len(results) == 1
    assert "vssadmin.exe" in results[0]["process"]["command_line"]

def test_qradar_integration():
    config = ConnectorConfig(
        connector_id="qradar-ariel-prod",
        vendor="qradar",
        product="qradar_siem",
        credentials={"host": "https://qradar-sandbox.internal", "port": 443, "sec_token": "token123", "mock": False}
    )
    connector = ConnectorRegistry.get("qradar")(config)
    assert connector.validate_connection() is True
    
    results = connector.query("SELECT * FROM events")
    assert len(results) == 1
    assert results[0]["payload"] == "modbus"

def test_crowdstrike_integration():
    config = ConnectorConfig(
        connector_id="crowdstrike-lql-prod",
        vendor="crowdstrike",
        product="logscale",
        credentials={"host": "https://crowdstrike-sandbox.internal", "token": "cs123", "mock": False}
    )
    connector = ConnectorRegistry.get("crowdstrike")(config)
    assert connector.validate_connection() is True
    
    results = connector.query("#event_simpleName=*")
    assert len(results) == 1
    assert results[0]["CommandLine"] == "msiexec.exe"
