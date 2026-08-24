from typing import List, Dict, Any

import httpx

from app.connector.base_connector import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
)
from app.connector.circuit_breaker import CircuitOpenError
from app.connector.exceptions import (
    ConnectorTransientError,
    ConnectorPermanentError,
    ConnectorResponseError,
)


class CrowdStrikeLogScaleConnector(BaseConnector):
    """
    CrowdStrike LogScale Connector.

    Provides:
        - Query execution
        - Query result polling
        - Connection validation
        - Centralized retry handling
        - Circuit breaker protection
        - Graceful fallback execution
    """

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        self.host = config.credentials.get(
            "host",
            "",
        ).rstrip("/")

        self.token = config.credentials.get("token")

        self.repository = config.scope.get(
            "repository",
            "",
        )

        self._last_job_id = None

    def _get_auth_headers(self) -> Dict[str, str]:
        if not self.token:
            raise ValueError(
                "CrowdStrike LogScale API token is required"
            )

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _get_query_url(self) -> str:
        if not self.host:
            raise ValueError(
                "CrowdStrike LogScale host is required"
            )

        if not self.repository:
            raise ValueError(
                "CrowdStrike LogScale repository is required"
            )

        return (
            f"{self.host}/api/v1/repositories/"
            f"{self.repository}/queryjobs"
        )

    def _get_query_result_url(self, job_id: str) -> str:
        if not job_id:
            raise ValueError(
                "Query job ID is required"
            )

        return (
            f"{self.host}/api/v1/repositories/"
            f"{self.repository}/queryjobs/{job_id}"
        )

    def _handle_http_error(
        self,
        error: httpx.HTTPStatusError,
    ) -> None:
        status_code = error.response.status_code

        if status_code == 429 or status_code >= 500:
            raise ConnectorTransientError(
                "CrowdStrike LogScale API returned "
                f"HTTP {status_code}"
            ) from error

        if 400 <= status_code < 500:
            raise ConnectorPermanentError(
                "CrowdStrike LogScale API returned "
                f"HTTP {status_code}"
            ) from error

        raise ConnectorResponseError(
            "CrowdStrike LogScale API returned "
            f"unexpected HTTP {status_code}"
        ) from error

    def _query_fallback(
        self,
        error: Exception,
    ) -> List[Dict[str, Any]]:
        """
        Gracefully degrade query execution for transient failures
        and an open circuit.

        Permanent/configuration errors remain visible.
        """

        if isinstance(error, ConnectorPermanentError):
            raise error

        if isinstance(error, ValueError):
            raise error

        if isinstance(error, ConnectorResponseError):
            raise error

        if isinstance(
            error,
            (
                ConnectorTransientError,
                CircuitOpenError,
            ),
        ):
            return []

        raise error

    def _poll_fallback(
        self,
        error: Exception,
    ) -> List[Dict[str, Any]]:
        """
        Gracefully degrade polling for transient failures
        and an open circuit.
        """

        if isinstance(error, ConnectorPermanentError):
            raise error

        if isinstance(error, ValueError):
            raise error

        if isinstance(error, ConnectorResponseError):
            raise error

        if isinstance(
            error,
            (
                ConnectorTransientError,
                CircuitOpenError,
            ),
        ):
            return []

        raise error

    def _validation_fallback(
        self,
        error: Exception,
    ) -> bool:
        """
        Return False for temporary connection failures or an open
        circuit while preserving permanent/configuration errors.
        """

        if isinstance(error, ConnectorPermanentError):
            raise error

        if isinstance(error, ValueError):
            raise error

        if isinstance(error, ConnectorResponseError):
            raise error

        if isinstance(
            error,
            (
                ConnectorTransientError,
                CircuitOpenError,
            ),
        ):
            return False

        raise error

    def query(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        """
        Execute a LogScale query through the centralized
        resilience framework.
        """

        if not query_str or not query_str.strip():
            raise ValueError(
                "Query cannot be empty"
            )

        if len(time_range) != 2:
            raise ValueError(
                "time_range must contain start and end values"
            )

        return self.execute_with_resilience(
            self._query_remote,
            query_str,
            time_range,
            fallback=self._query_fallback,
        )

    def _query_remote(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        start, end = time_range

        payload = {
            "queryString": query_str,
            "start": start,
            "end": end,
            "isLive": False,
        }

        try:
            response = httpx.post(
                self._get_query_url(),
                headers=self._get_auth_headers(),
                json=payload,
                timeout=30.0,
            )

            response.raise_for_status()

        except httpx.HTTPStatusError as error:
            self._handle_http_error(error)

        except httpx.TimeoutException as error:
            raise ConnectorTransientError(
                "CrowdStrike LogScale API request timed out"
            ) from error

        except httpx.RequestError as error:
            raise ConnectorTransientError(
                "Failed to connect to CrowdStrike LogScale API"
            ) from error

        try:
            result = response.json()
        except ValueError as error:
            raise ConnectorResponseError(
                "CrowdStrike LogScale API returned invalid JSON"
            ) from error

        if not isinstance(result, dict):
            raise ConnectorResponseError(
                "CrowdStrike LogScale query response "
                "has an unexpected format"
            )

        self._last_job_id = result.get("id")

        if not self._last_job_id:
            raise ConnectorResponseError(
                "CrowdStrike LogScale query response "
                "did not contain a query job ID"
            )

        return [result]

    def poll(self) -> List[Dict[str, Any]]:
        """
        Poll the latest CrowdStrike LogScale query job through
        the centralized resilience framework.
        """

        if not self._last_job_id:
            raise ValueError(
                "No query job is available to poll"
            )

        return self.execute_with_resilience(
            self._poll_remote,
            fallback=self._poll_fallback,
        )

    def _poll_remote(self) -> List[Dict[str, Any]]:
        try:
            response = httpx.get(
                self._get_query_result_url(
                    self._last_job_id
                ),
                headers=self._get_auth_headers(),
                timeout=30.0,
            )

            response.raise_for_status()

        except httpx.HTTPStatusError as error:
            self._handle_http_error(error)

        except httpx.TimeoutException as error:
            raise ConnectorTransientError(
                "CrowdStrike LogScale polling request timed out"
            ) from error

        except httpx.RequestError as error:
            raise ConnectorTransientError(
                "CrowdStrike LogScale polling request failed"
            ) from error

        try:
            result = response.json()
        except ValueError as error:
            raise ConnectorResponseError(
                "CrowdStrike LogScale polling returned invalid JSON"
            ) from error

        if isinstance(result, list):
            return result

        if isinstance(result, dict):
            events = result.get("events")

            if isinstance(events, list):
                return events

            return [result]

        raise ConnectorResponseError(
            "CrowdStrike LogScale polling response "
            "has an unexpected format"
        )

    def validate_connection(self) -> bool:
        """
        Validate CrowdStrike LogScale connectivity through the
        centralized resilience framework.
        """

        return self.execute_with_resilience(
            self._validate_connection_remote,
            fallback=self._validation_fallback,
        )

    def _validate_connection_remote(self) -> bool:
        try:
            response = httpx.get(
                self._get_query_url(),
                headers=self._get_auth_headers(),
                timeout=30.0,
            )

            response.raise_for_status()

        except httpx.HTTPStatusError as error:
            self._handle_http_error(error)

        except httpx.TimeoutException as error:
            raise ConnectorTransientError(
                "CrowdStrike LogScale connection request timed out"
            ) from error

        except httpx.RequestError as error:
            raise ConnectorTransientError(
                "Failed to connect to CrowdStrike LogScale API"
            ) from error

        return response.status_code == 200


ConnectorRegistry.register(
    "crowdstrike_logscale",
    CrowdStrikeLogScaleConnector,
)