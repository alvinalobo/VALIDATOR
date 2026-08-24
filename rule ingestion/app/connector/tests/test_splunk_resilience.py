import pytest

from app.connector.base_connector import ConnectorConfig
from app.connector.circuit_breaker import CircuitOpenError, CircuitState
from app.connector.exceptions import ConnectorTransientError
from app.connector.splunk_connector import SplunkConnector


def create_splunk_connector():
    config = ConnectorConfig(
        connector_id="splunk-resilience-test",
        vendor="splunk",
        product="siem",
        credentials={
            "host": "http://splunk-test",
            "port": 8089,
            "token": "test-token",
            "mock": False,
        },
    )

    return SplunkConnector(config)


def test_query_fallback_after_timeout(monkeypatch):
    connector = create_splunk_connector()

    attempts = {"count": 0}

    def failing_query(*args, **kwargs):
        attempts["count"] += 1
        raise ConnectorTransientError("Splunk endpoint timeout")

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert result == []
    assert attempts["count"] == 4
    assert connector.circuit_failure_count == 1
    assert connector.circuit_state == CircuitState.CLOSED


def test_circuit_opens_after_repeated_failures(monkeypatch):
    connector = create_splunk_connector()

    # Make the circuit open after two failed executions.
    connector.resilience.circuit_breaker.failure_threshold = 2

    attempts = {"count": 0}

    def failing_query(*args, **kwargs):
        attempts["count"] += 1
        raise ConnectorTransientError("Splunk service unavailable")

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    first_result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    second_result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert first_result == []
    assert second_result == []

    assert connector.circuit_state == CircuitState.OPEN
    assert connector.circuit_failure_count == 2


def test_open_circuit_blocks_remote_execution(monkeypatch):
    connector = create_splunk_connector()

    connector.resilience.circuit_breaker.failure_threshold = 1

    calls = {"count": 0}

    def failing_query(*args, **kwargs):
        calls["count"] += 1
        raise ConnectorTransientError("Splunk timeout")

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    # First call fails and opens the circuit.
    result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert result == []
    assert connector.circuit_state == CircuitState.OPEN
    assert calls["count"] == 4

    # Second call should not reach the remote operation.
    result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert result == []
    assert calls["count"] == 4
    assert connector.circuit_state == CircuitState.OPEN


def test_validate_connection_fallback_returns_false(monkeypatch):
    connector = create_splunk_connector()

    def failing_validation():
        raise ConnectorTransientError(
            "Splunk connection timeout"
        )

    monkeypatch.setattr(
        connector,
        "_validate_connection_remote",
        failing_validation,
    )

    result = connector.validate_connection()

    assert result is False
    assert connector.circuit_failure_count == 1
    assert connector.circuit_state == CircuitState.CLOSED


def test_circuit_reset_allows_remote_execution_again(monkeypatch):
    connector = create_splunk_connector()

    connector.resilience.circuit_breaker.failure_threshold = 1

    calls = {"count": 0}

    def failing_query(*args, **kwargs):
        calls["count"] += 1
        raise ConnectorTransientError("Splunk unavailable")

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    # Open the circuit.
    connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert connector.circuit_state == CircuitState.OPEN

    # Reset the circuit.
    connector.reset_resilience()

    assert connector.circuit_state == CircuitState.CLOSED
    assert connector.circuit_failure_count == 0

    # Remote operation is allowed again.
    result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert result == []
    assert calls["count"] == 8
    assert connector.circuit_failure_count == 1