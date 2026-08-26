import pytest
import time
from app.connector.base_connector import ConnectorConfig, ConnectorRegistry
from app.connector.qradar_connector import QRadarConnector
from app.connector.splunk_connector import SplunkConnector
from app.connector.elastic_connector import ElasticConnector, _detect_query_language
from app.connector.exceptions import ConnectorTransientError, ConnectorPermanentError
from conftest import MOCK_SERVER_STATE

# ----------------- SPLUNK TESTS -----------------

def test_splunk_mock_mode_query():
    """Verify Splunk mock mode correctly parses query and matches telemetry."""
    config = ConnectorConfig(
        connector_id="splunk-mock-1",
        vendor="splunk",
        product="siem",
        credentials={"mock": True}
    )
    connector = SplunkConnector(config)
    assert connector.is_mock is True
    assert connector.validate_connection() is True

    # Test "-encrypt" query (WORKSTATION-01)
    results_encrypt = connector.query("CommandLine matches -encrypt")
    assert len(results_encrypt) == 1
    assert results_encrypt[0]["host"] == "WORKSTATION-01"

    # Test "msiexec" query (WORKSTATION-02)
    results_msi = connector.query("Image matches msiexec")
    assert len(results_msi) == 1
    assert results_msi[0]["host"] == "WORKSTATION-02"

    # Test query returning no matches
    results_none = connector.query("vssadmin.exe and msiexec")
    assert len(results_none) == 0

def test_splunk_integration_mode_query(mock_server_url):
    """Verify Splunk queries hit the REST endpoints when not in mock mode."""
    host_part = mock_server_url.rsplit(":", 1)[0]
    port_part = int(mock_server_url.rsplit(":", 1)[1])
    config = ConnectorConfig(
        connector_id="splunk-real-1",
        vendor="splunk",
        product="siem",
        credentials={
            "host": host_part,
            "port": port_part,
            "token": "test-token",
            "mock": False
        }
    )
    connector = SplunkConnector(config)
    assert connector.is_mock is False
    assert connector.validate_connection() is True

    # Run query
    results = connector.query("index=windows")
    assert len(results) == 1
    assert results[0]["_raw"] == "splunk_test"
    assert MOCK_SERVER_STATE["splunk_dispatch_status_calls"] == 1

def test_splunk_poll_mechanism(mock_server_url):
    """Verify the Splunk poll helper works and updates last poll timestamp."""
    host_part = mock_server_url.rsplit(":", 1)[0]
    port_part = int(mock_server_url.rsplit(":", 1)[1])
    config = ConnectorConfig(
        connector_id="splunk-poll-1",
        vendor="splunk",
        product="siem",
        credentials={
            "host": host_part,
            "port": port_part,
            "token": "test-token",
            "mock": False
        }
    )
    connector = SplunkConnector(config)
    assert connector._last_poll_ts is None
    
    events = connector.poll()
    assert len(events) == 1
    assert connector._last_poll_ts is not None


# ----------------- ELASTIC DETECT LANGUAGE TESTS -----------------

@pytest.mark.parametrize(
    "query_str,expected_lang",
    [
        ("process where process.name == 'cmd.exe'", "eql"),
        ("file where file.extension == 'dll'", "eql"),
        ("sequence by host.name [process where process.name == 'cmd.exe']", "eql"),
        ("host.name: \"WORKSTATION-01\"", "kql"),
        ("event.code: 4624 AND winlog.event_data.subStatus: 0xC000005E", "kql"),
        ("index=* | head 10", "kql"),
    ]
)
def test_elastic_language_detection(query_str, expected_lang):
    """Verify query language is correctly classified as EQL or KQL."""
    assert _detect_query_language(query_str) == expected_lang


# ----------------- ELASTIC TESTS -----------------

def test_elastic_kql_query(mock_server_url):
    """Verify Elastic KQL query targets the standard search API."""
    config = ConnectorConfig(
        connector_id="elastic-1",
        vendor="elastic",
        product="siem",
        credentials={
            "base_url": mock_server_url,
            "api_key": "elastic-key"
        },
        scope={"index": "logs-*"}
    )
    connector = ElasticConnector(config)
    
    # KQL query
    results = connector.query("host.name: workstation-01", (1000, 2000))
    assert len(results) == 1
    assert results[0]["event"] == "kql_test"

def test_elastic_eql_query(mock_server_url):
    """Verify Elastic EQL query targets the _eql/search API."""
    config = ConnectorConfig(
        connector_id="elastic-2",
        vendor="elastic",
        product="siem",
        credentials={
            "base_url": mock_server_url,
            "api_key": "elastic-key"
        },
        scope={"index": "logs-*"}
    )
    connector = ElasticConnector(config)
    
    # EQL query
    results = connector.query("process where process.name == 'vssadmin.exe'", (1000, 2000))
    assert len(results) == 1
    assert results[0]["event"] == "eql_test"

def test_elastic_validation_success(mock_server_url):
    """Verify successful validation on status code 200."""
    config = ConnectorConfig(
        connector_id="elastic-3",
        vendor="elastic",
        product="siem",
        credentials={
            "base_url": mock_server_url,
            "api_key": "elastic-key"
        }
    )
    connector = ElasticConnector(config)
    assert connector.validate_connection() is True
    assert MOCK_SERVER_STATE["elastic_health_calls"] == 1

def test_elastic_validation_permanent_error(mock_server_url):
    """Verify immediate failure on credentials rejection (401/403) without retries."""
    config = ConnectorConfig(
        connector_id="elastic-4",
        vendor="elastic",
        product="siem",
        credentials={
            "base_url": mock_server_url,
            "api_key": "invalid-key"
        }
    )
    MOCK_SERVER_STATE["elastic_health_status"] = 401
    connector = ElasticConnector(config)
    
    with pytest.raises(ConnectorPermanentError) as exc_info:
        connector.validate_connection()
    assert "Elastic rejected the API key" in str(exc_info.value)
    # Permanent errors should not retry
    assert MOCK_SERVER_STATE["elastic_health_calls"] == 1

def test_elastic_validation_transient_retry_success(mock_server_url):
    """Verify retry handles transient errors that recover (e.g. 500, 503 -> 200)."""
    config = ConnectorConfig(
        connector_id="elastic-5",
        vendor="elastic",
        product="siem",
        credentials={
            "base_url": mock_server_url,
            "api_key": "elastic-key"
        }
    )
    # First two attempts return 500, third returns 200
    MOCK_SERVER_STATE["elastic_health_status"] = [500, 503, 200]
    
    # Temporarily monkeypatch time.sleep to run tests instantly
    import sys
    original_sleep = time.sleep
    time.sleep = lambda s: None
    
    try:
        connector = ElasticConnector(config)
        assert connector.validate_connection() is True
        assert MOCK_SERVER_STATE["elastic_health_calls"] == 3
    finally:
        time.sleep = original_sleep

def test_elastic_validation_transient_retry_exhausted(mock_server_url):
    """Verify retry exhaustes limits on persistent transient errors."""
    config = ConnectorConfig(
        connector_id="elastic-6",
        vendor="elastic",
        product="siem",
        credentials={
            "base_url": mock_server_url,
            "api_key": "elastic-key"
        }
    )
    # Always return 500 Internal Server Error
    MOCK_SERVER_STATE["elastic_health_status"] = 500
    
    import sys
    original_sleep = time.sleep
    time.sleep = lambda s: None
    
    try:
        connector = ElasticConnector(config)
        with pytest.raises(ConnectorTransientError) as exc_info:
            connector.validate_connection()
        assert "Elastic health check returned 500" in str(exc_info.value)
        # validator retry max_attempts is 3
        assert MOCK_SERVER_STATE["elastic_health_calls"] == 3
    finally:
        time.sleep = original_sleep


# ----------------- REGISTRY TESTS -----------------

def test_registry_integration():
    """Verify registry has both Splunk and Elastic connectors registered."""
    splunk_cls = ConnectorRegistry.get("splunk")
    assert splunk_cls == SplunkConnector

    elastic_cls = ConnectorRegistry.get("elastic")
    assert elastic_cls == ElasticConnector

    with pytest.raises(KeyError):
        ConnectorRegistry.get("nonexistent")


# ---------------- QRADAR TESTS ----------------

def test_qradar_mock_mode():
    """Verify QRadar connector works in mock mode."""

    config = ConnectorConfig(
        connector_id="qradar-test",
        vendor="ibm",
        product="qradar",
        credentials={"mock": True},
    )

    connector = QRadarConnector(config)

    assert connector.is_mock is True
    assert connector.validate_connection() is True


def test_qradar_query():
    """Verify QRadar mock query returns events."""

    config = ConnectorConfig(
        connector_id="qradar-test",
        vendor="ibm",
        product="qradar",
        credentials={"mock": True},
    )

    connector = QRadarConnector(config)

    results = connector.query("SELECT * FROM events")

    assert isinstance(results, list)
    assert len(results) > 0

    assert "sourceip" in results[0]
    assert "destinationip" in results[0]
    assert "eventname" in results[0]


def test_qradar_poll():
    """Verify QRadar polling returns mock events."""

    config = ConnectorConfig(
        connector_id="qradar-test",
        vendor="ibm",
        product="qradar",
        credentials={"mock": True},
    )

    connector = QRadarConnector(config)

    results = connector.poll()

    assert isinstance(results, list)
    assert len(results) > 0


def test_qradar_registry():
    """Verify QRadar connector is registered."""

    connector_cls = ConnectorRegistry.get("qradar")

    assert connector_cls is QRadarConnector
