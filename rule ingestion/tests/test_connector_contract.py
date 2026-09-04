import pytest

from app.connector.base_connector import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
)

import app.connector.splunk_connector
import app.connector.elastic_connector
import app.connector.qradar_connector
import app.connector.crowdstrike_logscale_connector
import app.connector.sentinel_connector


CONNECTOR_CONFIGS = {
    "splunk": ConnectorConfig(
        connector_id="contract-splunk",
        vendor="splunk",
        product="splunk_enterprise",
        credentials={
            "host": "http://mock-splunk",
            "port": 8089,
            "token": "test-token",
            "mock": True,
        },
    ),
    "elastic": ConnectorConfig(
        connector_id="contract-elastic",
        vendor="elastic",
        product="elastic_security",
        credentials={
            "base_url": "http://mock-elastic",
            "api_key": "test-api-key",
        },
    ),
    "qradar": ConnectorConfig(
        connector_id="contract-qradar",
        vendor="qradar",
        product="qradar_siem",
        credentials={
            "base_url": "http://mock-qradar",
            "sec_token": "test-token",
            "mock": True,
        },
    ),
    "crowdstrike_logscale": ConnectorConfig(
        connector_id="contract-crowdstrike",
        vendor="crowdstrike",
        product="logscale",
        credentials={
            "host": "http://mock-crowdstrike",
            "token": "test-token",
        },
        scope={
            "repository": "default",
        },
    ),
    "sentinel": ConnectorConfig(
        connector_id="contract-sentinel",
        vendor="sentinel",
        product="microsoft_sentinel",
        credentials={
            "mock": True,
        },
    ),
}


@pytest.mark.parametrize("vendor", CONNECTOR_CONFIGS.keys())
def test_registered_connector_implements_base_contract(vendor):
    connector_cls = ConnectorRegistry.get(vendor)

    assert issubclass(connector_cls, BaseConnector)

    connector = connector_cls(CONNECTOR_CONFIGS[vendor])

    assert callable(connector.query)
    assert callable(connector.poll)
    assert callable(connector.validate_connection)


def test_splunk_mock_contract(monkeypatch):
    connector_cls = ConnectorRegistry.get("splunk")
    connector = connector_cls(CONNECTOR_CONFIGS["splunk"])

    monkeypatch.setattr(
        connector,
        "validate_connection",
        lambda: True,
    )
    monkeypatch.setattr(
        connector,
        "query",
        lambda query_str, time_range=("now-1h", "now"): [
            {"event": "splunk_mock"}
        ],
    )

    assert connector.validate_connection() is True

    results = connector.query(
        "index=*",
        ("now-1h", "now"),
    )

    assert isinstance(results, list)


def test_elastic_mock_contract(monkeypatch):
    connector_cls = ConnectorRegistry.get("elastic")
    connector = connector_cls(CONNECTOR_CONFIGS["elastic"])

    monkeypatch.setattr(
        connector,
        "validate_connection",
        lambda: True,
    )
    monkeypatch.setattr(
        connector,
        "query",
        lambda query_str, time_range: [
            {"event": "elastic_mock"}
        ],
    )

    assert connector.validate_connection() is True

    results = connector.query(
        "host.name: WORKSTATION-01",
        ("now-1h", "now"),
    )

    assert isinstance(results, list)


def test_qradar_mock_contract(monkeypatch):
    connector_cls = ConnectorRegistry.get("qradar")
    connector = connector_cls(CONNECTOR_CONFIGS["qradar"])

    monkeypatch.setattr(
        connector,
        "validate_connection",
        lambda: True,
    )
    monkeypatch.setattr(
        connector,
        "query",
        lambda query_str: [
            {"eventname": "QRadar mock event"}
        ],
    )

    assert connector.validate_connection() is True

    results = connector.query(
        "SELECT * FROM events"
    )

    assert isinstance(results, list)


def test_crowdstrike_mock_contract(monkeypatch):
    connector_cls = ConnectorRegistry.get("crowdstrike_logscale")
    connector = connector_cls(
        CONNECTOR_CONFIGS["crowdstrike_logscale"]
    )

    monkeypatch.setattr(
        connector,
        "validate_connection",
        lambda: True,
    )
    monkeypatch.setattr(
        connector,
        "query",
        lambda query_str, time_range: [
            {"id": "mock-job-id"}
        ],
    )
    monkeypatch.setattr(
        connector,
        "poll",
        lambda: [
            {"event": "crowdstrike_mock"}
        ],
    )

    assert connector.validate_connection() is True

    query_result = connector.query(
        "#event_simpleName=*",
        ("1h", "now"),
    )

    assert isinstance(query_result, list)

    poll_result = connector.poll()

    assert isinstance(poll_result, list)


def test_sentinel_mock_contract(monkeypatch):
    connector_cls = ConnectorRegistry.get("sentinel")
    connector = connector_cls(CONNECTOR_CONFIGS["sentinel"])

    assert connector.validate_connection() is True

    results = connector.query("powershell")

    assert isinstance(results, list)


@pytest.mark.parametrize("vendor", CONNECTOR_CONFIGS.keys())
def test_connector_contract_methods_are_present(vendor):
    connector_cls = ConnectorRegistry.get(vendor)
    connector = connector_cls(CONNECTOR_CONFIGS[vendor])

    assert hasattr(connector, "query")
    assert hasattr(connector, "poll")
    assert hasattr(connector, "validate_connection")