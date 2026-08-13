import httpx
import pytest

from app.connector.exceptions import (
    ConnectorTransientError,
    ConnectorPermanentError,
)
from app.connector.base_connector import ConnectorConfig
from app.connector.crowdstrike_logscale_connector import (
    CrowdStrikeLogScaleConnector,
)


def create_connector():
    config = ConnectorConfig(
        connector_id="test-crowdstrike",
        vendor="crowdstrike",
        product="logscale",
        credentials={
            "host": "https://example.logscale.test",
            "token": "test-token",
        },
        scope={
            "repository": "test-repository",
        },
    )

    return CrowdStrikeLogScaleConnector(config)


def test_query_success(monkeypatch):
    connector = create_connector()

    expected_response = {
        "id": "test-job-id",
    }

    def mock_post(*args, **kwargs):
        assert args[0] == (
            "https://example.logscale.test/"
            "api/v1/repositories/test-repository/queryjobs"
        )

        assert kwargs["headers"]["Authorization"] == "Bearer test-token"

        assert kwargs["json"] == {
            "queryString": "hello",
            "start": "1h",
            "end": "now",
            "isLive": False,
        }

        return httpx.Response(
            200,
            json=expected_response,
            request=httpx.Request("POST", args[0]),
        )

    monkeypatch.setattr(httpx, "post", mock_post)

    result = connector.query(
        "hello",
        ("1h", "now"),
    )

    assert result == [expected_response]
    assert connector._last_job_id == "test-job-id"


def test_query_rejects_empty_query():
    connector = create_connector()

    with pytest.raises(ValueError, match="Query cannot be empty"):
        connector.query("", ("1h", "now"))


def test_query_requires_two_time_values():
    connector = create_connector()

    with pytest.raises(
        ValueError,
        match="time_range must contain start and end values",
    ):
        connector.query("hello", ("1h",))


def test_poll_success(monkeypatch):
    connector = create_connector()
    connector._last_job_id = "test-job-id"

    expected_events = [
        {"message": "test event"}
    ]

    def mock_get(*args, **kwargs):
        assert args[0] == (
            "https://example.logscale.test/"
            "api/v1/repositories/test-repository/"
            "queryjobs/test-job-id"
        )

        assert kwargs["headers"]["Authorization"] == "Bearer test-token"

        return httpx.Response(
            200,
            json={
                "status": "completed",
                "events": expected_events,
            },
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    result = connector.poll()

    assert result == expected_events


def test_poll_without_job_id():
    connector = create_connector()

    with pytest.raises(
        ValueError,
        match="No query job is available to poll",
    ):
        connector.poll()


def test_validate_connection_success(monkeypatch):
    connector = create_connector()

    def mock_get(*args, **kwargs):
        return httpx.Response(
            200,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    assert connector.validate_connection() is True


def test_validate_connection_failure(monkeypatch):
    connector = create_connector()

    def mock_get(*args, **kwargs):
        return httpx.Response(
            401,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    assert connector.validate_connection() is False


def test_query_raises_permanent_error_on_401(monkeypatch):
    connector = create_connector()

    def mock_post(*args, **kwargs):
        return httpx.Response(
            401,
            request=httpx.Request("POST", args[0]),
        )

    monkeypatch.setattr(httpx, "post", mock_post)

    with pytest.raises(ConnectorPermanentError):
        connector.query("hello", ("1h", "now"))


def test_query_raises_transient_error_on_500(monkeypatch):
    connector = create_connector()

    def mock_post(*args, **kwargs):
        return httpx.Response(
            500,
            request=httpx.Request("POST", args[0]),
        )

    monkeypatch.setattr(httpx, "post", mock_post)

    with pytest.raises(ConnectorTransientError):
        connector.query("hello", ("1h", "now"))


def test_query_raises_transient_error_on_429(monkeypatch):
    connector = create_connector()

    def mock_post(*args, **kwargs):
        return httpx.Response(
            429,
            request=httpx.Request("POST", args[0]),
        )

    monkeypatch.setattr(httpx, "post", mock_post)

    with pytest.raises(ConnectorTransientError):
        connector.query("hello", ("1h", "now"))


def test_poll_raises_permanent_error_on_404(monkeypatch):
    connector = create_connector()
    connector._last_job_id = "test-job-id"

    def mock_get(*args, **kwargs):
        return httpx.Response(
            404,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    with pytest.raises(ConnectorPermanentError):
        connector.poll()


def test_query_raises_transient_error_on_network_failure(monkeypatch):
    connector = create_connector()

    def mock_post(*args, **kwargs):
        raise httpx.ConnectError("Connection failed")

    monkeypatch.setattr(httpx, "post", mock_post)

    with pytest.raises(ConnectorTransientError):
        connector.query("hello", ("1h", "now"))


def test_poll_returns_events_from_response(monkeypatch):
    connector = create_connector()
    connector._last_job_id = "test-job-id"

    expected_events = [
        {"message": "event one"},
        {"message": "event two"},
    ]

    def mock_get(*args, **kwargs):
        return httpx.Response(
            200,
            json={
                "status": "completed",
                "events": expected_events,
            },
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    result = connector.poll()

    assert result == expected_events


def test_poll_returns_list_response(monkeypatch):
    connector = create_connector()
    connector._last_job_id = "test-job-id"

    expected_events = [
        {"message": "event one"},
        {"message": "event two"},
    ]

    def mock_get(*args, **kwargs):
        return httpx.Response(
            200,
            json=expected_events,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    result = connector.poll()

    assert result == expected_events


def test_poll_returns_dict_when_events_are_missing(monkeypatch):
    connector = create_connector()
    connector._last_job_id = "test-job-id"

    expected_response = {
        "status": "running",
    }

    def mock_get(*args, **kwargs):
        return httpx.Response(
            200,
            json=expected_response,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    result = connector.poll()

    assert result == [expected_response]