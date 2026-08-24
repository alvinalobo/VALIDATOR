import pytest
import httpx
from app.connector.base_connector import ConnectorConfig, ConnectorRegistry
import app.connector.splunk_connector
import app.connector.elastic_connector
import app.connector.qradar_connector
import app.connector.crowdstrike_logscale_connector
 
 
class MockResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json_data = json_data
 
    def json(self):
        return self._json_data
 
 
def mock_send(self_client, request, *args, **kwargs):
    url_str = str(request.url)
 
    if "/services/search/jobs" in url_str:
        if "/results" in url_str:
            return MockResponse(200, {"results": [{"host": "WORKSTATION-01", "CommandLine": "vssadmin.exe -encrypt"}]})
        elif "splunk-test-sid-123" in url_str:
            return MockResponse(200, {"entry": [{"content": {"dispatchState": "DONE"}}]})
        else:
            return MockResponse(201, {"sid": "splunk-test-sid-123"})
    elif "/services/authentication/current-context" in url_str:
        return MockResponse(200, {})
    elif "/_eql/search" in url_str or "/_search" in url_str:
        return MockResponse(200, {
            "hits": {
                "events": [{"_source": {"process": {"command_line": "vssadmin.exe -encrypt"}}}],
                "hits": [{"_source": {"process": {"command_line": "vssadmin.exe -encrypt"}}}]
            }
        })
    elif "/api/ariel/searches" in url_str:
        if "/results" in url_str:
            return MockResponse(200, {"events": [{"sourceip": "192.168.1.50", "payload": "modbus"}]})
        elif "qradar-test-sid-456" in url_str:
            return MockResponse(200, {"status": "COMPLETED"})
        else:
            return MockResponse(201, {"search_id": "qradar-test-sid-456"})
    elif "/api/v1/repositories" in url_str:
        return MockResponse(200, [{"CommandLine": "msiexec.exe"}])
 
    return MockResponse(404, {"error": "Endpoint not simulated"})
 
 
@pytest.fixture(autouse=True)
def mock_httpx_client(monkeypatch):
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
 
 
def test_elastic_integration():
    config = ConnectorConfig(
        connector_id="elastic-sec-prod",
        vendor="elastic",
        product="elastic_security",
        credentials={"base_url": "https://elastic-sandbox.internal", "api_key": "key123"}
    )
    connector = ConnectorRegistry.get("elastic")(config)
    assert connector.validate_connection() is True
 
    results = connector.query("process.name: *", (1000, 2000))
    assert len(results) == 1
    assert "vssadmin.exe" in results[0]["process"]["command_line"]
 
 
def test_qradar_integration():
    config = ConnectorConfig(
        connector_id="qradar-ariel-prod",
        vendor="qradar",
        product="qradar_siem",
        credentials={"base_url": "https://qradar-sandbox.internal", "sec_token": "token123", "mock": False}
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
        credentials={"host": "https://crowdstrike-sandbox.internal", "token": "cs123"},
        scope={"repository": "default"}
    )
    connector = ConnectorRegistry.get("crowdstrike_logscale")(config)
    results = connector.query("#event_simpleName=*", ("1h", "now"))
    assert len(results) == 1
    assert results[0]["CommandLine"] == "msiexec.exe"
