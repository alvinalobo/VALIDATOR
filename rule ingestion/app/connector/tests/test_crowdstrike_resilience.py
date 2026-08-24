import pytest

from app.connector.base_connector import ConnectorConfig
from app.connector.circuit_breaker import CircuitState
from app.connector.exceptions import ConnectorTransientError
from app.connector.crowdstrike_logscale_connector import (
    CrowdStrikeLogScaleConnector,
)


def create_crowdstrike_connector():
    config = ConnectorConfig(
        connector_id="crowdstrike-resilience-test",
        vendor="crowdstrike",
        product="logscale",
        credentials={
            "host": "http://crowdstrike-test",
            "token": "test-token",
        },
        scope={
            "repository": "test-repository",
        },
    )

    connector = CrowdStrikeLogScaleConnector(config)

    # Make resilience tests fast.
    connector.resilience.base_delay = 0
    connector.resilience.max_delay = 0
    connector.resilience.jitter = 0

    return connector


def test_query_retries_then_uses_fallback(monkeypatch):
    connector = create_crowdstrike_connector()

    attempts = {"count": 0}

    def failing_query(*args, **kwargs):
        attempts["count"] += 1
        raise ConnectorTransientError(
            "CrowdStrike LogScale endpoint timeout"
        )

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    result = connector.query(
        "eventType=ProcessRollup",
        time_range=(None, None),
    )

    assert result == []

    # Default resilience retry limit is 4.
    assert attempts["count"] == 4

    assert connector.circuit_failure_count == 1
    assert connector.circuit_state == CircuitState.CLOSED


def test_circuit_opens_after_repeated_crowdstrike_failures(
    monkeypatch,
):
    connector = create_crowdstrike_connector()

    connector.resilience.circuit_breaker.failure_threshold = 2

    attempts = {"count": 0}

    def failing_query(*args, **kwargs):
        attempts["count"] += 1
        raise ConnectorTransientError(
            "CrowdStrike LogScale service unavailable"
        )

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    first_result = connector.query(
        "eventType=ProcessRollup",
        time_range=(None, None),
    )

    second_result = connector.query(
        "eventType=ProcessRollup",
        time_range=(None, None),
    )

    assert first_result == []
    assert second_result == []

    assert connector.circuit_state == CircuitState.OPEN
    assert connector.circuit_failure_count == 2

    # Two executions × four retry attempts.
    assert attempts["count"] == 8


def test_open_circuit_blocks_crowdstrike_request(monkeypatch):
    connector = create_crowdstrike_connector()

    connector.resilience.circuit_breaker.failure_threshold = 1

    calls = {"count": 0}

    def failing_query(*args, **kwargs):
        calls["count"] += 1
        raise ConnectorTransientError(
            "CrowdStrike LogScale timeout"
        )

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    # First request reaches the remote operation and opens the circuit.
    result = connector.query(
        "eventType=ProcessRollup",
        time_range=(None, None),
    )

    assert result == []
    assert connector.circuit_state == CircuitState.OPEN
    assert calls["count"] == 4

    # Second request must be blocked by the circuit breaker.
    result = connector.query(
        "eventType=ProcessRollup",
        time_range=(None, None),
    )

    assert result == []

    # No additional remote execution.
    assert calls["count"] == 4
    assert connector.circuit_state == CircuitState.OPEN


def test_poll_uses_fallback_on_transient_failure(monkeypatch):
    connector = create_crowdstrike_connector()

    connector._last_job_id = "test-job"

    attempts = {"count": 0}

    def failing_poll(*args, **kwargs):
        attempts["count"] += 1
        raise ConnectorTransientError(
            "CrowdStrike LogScale polling timeout"
        )

    monkeypatch.setattr(
        connector,
        "_poll_remote",
        failing_poll,
    )

    result = connector.poll()

    assert result == []

    assert attempts["count"] == 4
    assert connector.circuit_failure_count == 1
    assert connector.circuit_state == CircuitState.CLOSED


def test_validate_connection_uses_fallback(monkeypatch):
    connector = create_crowdstrike_connector()

    attempts = {"count": 0}

    def failing_validation():
        attempts["count"] += 1
        raise ConnectorTransientError(
            "CrowdStrike LogScale connection timeout"
        )

    monkeypatch.setattr(
        connector,
        "_validate_connection_remote",
        failing_validation,
    )

    result = connector.validate_connection()

    assert result is False

    assert attempts["count"] == 4
    assert connector.circuit_failure_count == 1
    assert connector.circuit_state == CircuitState.CLOSED


def test_reset_allows_crowdstrike_requests_again(monkeypatch):
    connector = create_crowdstrike_connector()

    connector.resilience.circuit_breaker.failure_threshold = 1

    calls = {"count": 0}

    def failing_query(*args, **kwargs):
        calls["count"] += 1
        raise ConnectorTransientError(
            "CrowdStrike LogScale unavailable"
        )

    monkeypatch.setattr(
        connector,
        "_query_remote",
        failing_query,
    )

    # Open the circuit.
    result = connector.query(
        "eventType=ProcessRollup",
        time_range=(None, None),
    )

    assert result == []
    assert connector.circuit_state == CircuitState.OPEN

    # Reset resilience state.
    connector.reset_resilience()

    assert connector.circuit_state == CircuitState.CLOSED
    assert connector.circuit_failure_count == 0

    # Request is allowed again.
    result = connector.query(
        "eventType=ProcessRollup",
        time_range=(None, None),
    )

    assert result == []

    # First execution = 4 attempts.
    # Second execution after reset = 4 attempts.
    assert calls["count"] == 8