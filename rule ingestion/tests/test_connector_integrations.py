import pytest
import httpx
import requests
from typing import Any
from app.connector.base_connector import ConnectorConfig, ConnectorRegistry
import app.connector.splunk_connector
import app.connector.elastic_connector
import app.connector.qradar_connector
import app.connector.crowdstrike_logscale_connector
import app.connector.sentinel_connector


class MockResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "Error",
                request=None,
                response=self
            )


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
    elif "/api/ariel/searches" in url_str:
        if "/results" in url_str:
            return MockResponse(200, {"events": [{"sourceip": "192.168.1.50", "payload": "modbus"}]})
        elif "qradar-test-sid-456" in url_str:
            return MockResponse(200, {"status": "COMPLETED"})
        elif request.method == "POST":
            return MockResponse(201, {"search_id": "qradar-test-sid-456"})
        else:
            return MockResponse(200, [])
    elif "/api/v1/repositories" in url_str:
        if "/queryjobs/" in url_str:
            # Polling endpoint
            return MockResponse(200, [{"CommandLine": "msiexec.exe"}])
        else:
            # Query start / health check endpoint
            if request.method == "POST":
                return MockResponse(200, {"id": "cs-job-id"})
            else:
                return MockResponse(200, {})

    return MockResponse(404, {"error": "Endpoint not simulated"})


class MockRequestsResponse:
    def __init__(self, status_code: int, json_data: Any):
        self.status_code = status_code
        self._json_data = json_data
        self.text = ""

    def json(self) -> Any:
        return self._json_data


def mock_requests_post(self_session, url: str, json: Any = None, **kwargs) -> MockRequestsResponse:
    if "/_eql/search" in url or "/_search" in url:
        return MockRequestsResponse(200, {
            "hits": {
                "events": [{"_source": {"process": {"command_line": "vssadmin.exe -encrypt"}}}],
                "hits": [{"_source": {"process": {"command_line": "vssadmin.exe -encrypt"}}}]
            }
        })
    return MockRequestsResponse(404, {})


def mock_requests_get(self_session, url: str, **kwargs) -> MockRequestsResponse:
    if "/_cluster/health" in url:
        return MockRequestsResponse(200, {})
    return MockRequestsResponse(404, {})


@pytest.fixture(autouse=True)
def mock_all_clients(monkeypatch):
    monkeypatch.setattr(httpx.Client, "send", mock_send)
    monkeypatch.setattr(requests.Session, "post", mock_requests_post)
    monkeypatch.setattr(requests.Session, "get", mock_requests_get)


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
    assert connector.validate_connection() is True

    # Initiate asynchronous query
    query_res = connector.query("#event_simpleName=*", ("1h", "now"))
    assert len(query_res) == 1
    assert query_res[0]["id"] == "cs-job-id"

    # Poll for events
    results = connector.poll()
    assert len(results) == 1
    assert results[0]["CommandLine"] == "msiexec.exe"

def test_sentinel_integration():
    config = ConnectorConfig(
        connector_id="sentinel-sandbox",
        vendor="sentinel",
        product="microsoft_sentinel",
        credentials={
            "mock": True
        }
    )

    connector = ConnectorRegistry.get("sentinel")(config)

    assert connector.validate_connection() is True

    results = connector.query("powershell")

    assert len(results) == 1
    assert results[0]["FileName"] == "powershell.exe"
