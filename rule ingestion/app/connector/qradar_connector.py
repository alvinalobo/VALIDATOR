import time
import httpx
from typing import List, Dict, Any

from app.connector.base_connector import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
)
from app.connector.exceptions import (
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorResponseError,
)


_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class QRadarConnector(BaseConnector):
    """
    IBM QRadar SIEM Connector.

    Supports:
        - AQL query execution
        - Ariel search creation
        - Ariel search polling
        - Ariel search result retrieval
        - Connection validation
        - Mock mode for offline testing
        - Centralized retry handling
        - Circuit breaker protection
        - Graceful fallback execution
    """

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        self.base_url = self.config.credentials.get(
            "base_url",
            "",
        ).rstrip("/")

        self.sec_token = self.config.credentials.get(
            "sec_token"
        )

        self.is_mock = self.config.credentials.get(
            "mock",
            not bool(self.base_url),
        )

        self.verify_ssl = self.config.credentials.get(
            "verify_ssl",
            False,
        )

        self.timeout = self.config.credentials.get(
            "timeout",
            30.0,
        )

        self.poll_interval = self.config.credentials.get(
            "poll_interval",
            1.0,
        )

        self.max_poll_attempts = self.config.credentials.get(
            "max_poll_attempts",
            30,
        )

    def _get_headers(self) -> Dict[str, str]:
        """Build QRadar REST API headers."""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self.sec_token:
            headers["SEC"] = self.sec_token

        return headers

    def _raise_for_status(
        self,
        response: httpx.Response,
        context: str,
        allowed_status_codes: set[int],
    ) -> None:
        """
        Convert QRadar HTTP failures into connector exceptions.

        Retryable:
            429 and 5xx

        Permanent:
            Other 4xx responses

        Response:
            Unexpected non-success responses.
        """

        if response.status_code in allowed_status_codes:
            return

        message = (
            f"{context}: HTTP {response.status_code} "
            f"{response.text[:200]}"
        )

        if response.status_code in _RETRYABLE_STATUS_CODES:
            raise ConnectorTransientError(message)

        if 400 <= response.status_code < 500:
            raise ConnectorPermanentError(message)

        raise ConnectorResponseError(message)

    def validate_connection(self) -> bool:
        """
        Verify QRadar credentials and API connectivity.

        Temporary failures are retried. After retries are exhausted,
        graceful degraded execution returns False.
        """

        if self.is_mock:
            return True

        return self.execute_with_resilience(
            self._validate_connection_remote,
            fallback=lambda error=None: False,
        )

    def _validate_connection_remote(self) -> bool:
        url = f"{self.base_url}/api/ariel/searches"

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=10.0,
            ) as client:

                response = client.get(
                    url,
                    headers=self._get_headers(),
                )

        except httpx.TimeoutException as exc:
            raise ConnectorTransientError(
                f"QRadar connection timeout: {exc}"
            ) from exc

        except httpx.NetworkError as exc:
            raise ConnectorTransientError(
                f"Could not reach QRadar: {exc}"
            ) from exc

        except httpx.HTTPError as exc:
            raise ConnectorTransientError(
                f"QRadar HTTP client error: {exc}"
            ) from exc

        self._raise_for_status(
            response,
            "QRadar connection validation failed",
            {200},
        )

        return True

    def query(
        self,
        query_str: str,
        time_range: tuple = (None, None),
    ) -> List[Dict[str, Any]]:
        """
        Execute an AQL query through the QRadar Ariel API.

        Lifecycle:
            1. Create Ariel search
            2. Poll search status
            3. Retrieve results

        Failures are handled through the centralized resilience layer.
        """

        if self.is_mock:
            return self._query_mock(
                query_str,
                time_range,
            )

        if not query_str or not query_str.strip():
            return []

        return self.execute_with_resilience(
            self._query_remote,
            query_str,
            time_range,
            fallback=lambda error=None: [],
        )

    def _query_remote(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        """
        Execute the actual QRadar remote query.

        Exceptions are intentionally propagated so the centralized
        resilience layer can handle retry, circuit breaking,
        and fallback.
        """

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=self.timeout,
            ) as client:

                # 1. Create Ariel search
                search_url = (
                    f"{self.base_url}/api/ariel/searches"
                )

                response = client.post(
                    search_url,
                    headers=self._get_headers(),
                    params={
                        "query_expression": query_str,
                    },
                )

                self._raise_for_status(
                    response,
                    "QRadar Ariel search creation failed",
                    {200, 201},
                )

                try:
                    search_data = response.json()
                except ValueError as exc:
                    raise ConnectorResponseError(
                        "QRadar returned invalid JSON while creating "
                        "the Ariel search"
                    ) from exc

                search_id = search_data.get("search_id")

                if not search_id:
                    raise ConnectorResponseError(
                        "QRadar Ariel search response did not contain "
                        "a search_id"
                    )

                # 2. Poll Ariel search
                status_url = (
                    f"{self.base_url}/api/ariel/searches/"
                    f"{search_id}"
                )

                completed = False

                for _ in range(self.max_poll_attempts):

                    status_response = client.get(
                        status_url,
                        headers=self._get_headers(),
                    )

                    self._raise_for_status(
                        status_response,
                        "QRadar Ariel search status request failed",
                        {200},
                    )

                    try:
                        status_data = status_response.json()
                    except ValueError as exc:
                        raise ConnectorResponseError(
                            "QRadar returned invalid JSON while polling "
                            "the Ariel search"
                        ) from exc

                    status = status_data.get(
                        "status",
                        "",
                    ).upper()

                    if status == "COMPLETED":
                        completed = True
                        break

                    if status in ("ERROR", "FAILED"):
                        raise ConnectorTransientError(
                            f"QRadar Ariel search failed with status "
                            f"{status}"
                        )

                    time.sleep(self.poll_interval)

                if not completed:
                    raise ConnectorTransientError(
                        "QRadar Ariel search did not complete within "
                        "the allowed polling window"
                    )

                # 3. Retrieve Ariel search results
                results_url = (
                    f"{self.base_url}/api/ariel/searches/"
                    f"{search_id}/results"
                )

                results_response = client.get(
                    results_url,
                    headers=self._get_headers(),
                )

                self._raise_for_status(
                    results_response,
                    "QRadar Ariel search results request failed",
                    {200},
                )

                try:
                    results_data = results_response.json()
                except ValueError as exc:
                    raise ConnectorResponseError(
                        "QRadar returned invalid JSON for Ariel "
                        "search results"
                    ) from exc

                return results_data.get(
                    "events",
                    [],
                )

        except httpx.TimeoutException as exc:
            raise ConnectorTransientError(
                f"QRadar query timeout: {exc}"
            ) from exc

        except httpx.NetworkError as exc:
            raise ConnectorTransientError(
                f"Could not reach QRadar: {exc}"
            ) from exc

        except httpx.HTTPError as exc:
            raise ConnectorTransientError(
                f"QRadar HTTP client error: {exc}"
            ) from exc

    def poll(self) -> List[Dict[str, Any]]:
        """
        Pull new QRadar events since the last poll.

        Uses a five-minute polling window and the resilient
        query path.
        """

        now = time.time()

        start_ts = (
            self._last_poll_ts
            if self._last_poll_ts is not None
            else now - 300
        )

        aql = (
            "SELECT * FROM events "
            f"START {int(start_ts * 1000)} "
            f"STOP {int(now * 1000)}"
        )

        results = self.query(
            aql,
            time_range=(start_ts, now),
        )

        self._last_poll_ts = now

        return results

    def _query_mock(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        """Mock QRadar AQL execution for offline testing."""

        mock_events = [
            {
                "sourceip": "192.168.1.10",
                "destinationip": "10.0.0.10",
                "username": "admin",
                "eventname": "Successful Login",
                "qid": 5001,
            },
            {
                "sourceip": "192.168.1.20",
                "destinationip": "10.0.0.20",
                "username": "user1",
                "eventname": "Failed Login",
                "qid": 5002,
            },
        ]

        return mock_events


ConnectorRegistry.register(
    "qradar",
    QRadarConnector,
)