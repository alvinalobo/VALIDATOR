import pytest

from app.connector.base_connector import ConnectorConfig
from app.connector.circuit_breaker import CircuitState
from app.connector.exceptions import ConnectorTransientError
from app.connector.elastic_connector import ElasticConnector


def create_elastic_connector():
    config = ConnectorConfig(
        connector_id="elastic-resilience-test",
        vendor="elastic",
        product="siem",
        credentials={
            "base_url": "http://elastic-test",
            "api_key": "test-key",
        },
    )

    connector = ElasticConnector(config)

    # Keep resilience tests fast.
    connector.resilience.base_delay = 0
    connector.resilience.max_delay = 0
    connector.resilience.jitter = 0

    return connector


def test_query_retries_then_uses_fallback(monkeypatch):
    connector = create_elastic_connector()

    attempts = {"count": 0}

    def failing_query(*args, **kwargs):
        attempts["count"] += 1
        raise ConnectorTransientError(
            "Elastic endpoint timeout"
        )

    monkeypatch.setattr(
        connector,
        "_query_kql",
        failing_query,
    )

    result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert result == []

    # Default resilience retry limit is 4.
    assert attempts["count"] == 4

    # One failed execution is recorded by the circuit breaker.
    assert connector.circuit_failure_count == 1
    assert connector.circuit_state == CircuitState.CLOSED


def test_circuit_opens_after_repeated_elastic_failures(monkeypatch):
    connector = create_elastic_connector()

    connector.resilience.circuit_breaker.failure_threshold = 2

    attempts = {"count": 0}

    def failing_query(*args, **kwargs):
        attempts["count"] += 1
        raise ConnectorTransientError(
            "Elastic service unavailable"
        )

    monkeypatch.setattr(
        connector,
        "_query_kql",
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

    # Each successful execution attempt reached the retry layer.
    assert attempts["count"] == 8


def test_open_circuit_blocks_elastic_request(monkeypatch):
    connector = create_elastic_connector()

    connector.resilience.circuit_breaker.failure_threshold = 1

    calls = {"count": 0}

    def failing_query(*args, **kwargs):
        calls["count"] += 1
        raise ConnectorTransientError(
            "Elastic timeout"
        )

    monkeypatch.setattr(
        connector,
        "_query_kql",
        failing_query,
    )

    # First request reaches the operation and opens the circuit.
    result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert result == []
    assert connector.circuit_state == CircuitState.OPEN
    assert calls["count"] == 4

    # Second request must be blocked by the circuit breaker.
    result = connector.query(
        "index=*",
        time_range=(None, None),
    )

    assert result == []

    # No additional remote execution.
    assert calls["count"] == 4
    assert connector.circuit_state == CircuitState.OPEN


def test_elastic_validation_retries_three_times(monkeypatch):
    connector = create_elastic_connector()

    attempts = {"count": 0}

    def failing_validation():
        attempts["count"] += 1
        raise ConnectorTransientError(
            "Elastic health check timeout"
        )

    monkeypatch.setattr(
        connector,
        "_validate_connection_remote",
        failing_validation,
    )

    with pytest.raises(
        ConnectorTransientError,
        match="Elastic health check timeout",
    ):
        connector.validate_connection()

    # validate_connection explicitly uses max_attempts=3.
    assert attempts["count"] == 3


def test_reset_allows_elastic_requests_again(monkeypatch):
    connector = create_elastic_connector()

    connector.resilience.circuit_breaker.failure_threshold = 1

    calls = {"count": 0}

    def failing_query(*args, **kwargs):
        calls["count"] += 1
        raise ConnectorTransientError(
            "Elastic unavailable"
        )

    monkeypatch.setattr(
        connector,
        "_query_kql",
        failing_query,
    )

    # Open the circuit.
    result = connector.query(
        "index=*",
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
        "index=*",
        time_range=(None, None),
    )

    assert result == []
    assert calls["count"] == 8