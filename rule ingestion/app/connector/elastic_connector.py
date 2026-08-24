import re
import time
from typing import Any, Dict, List

import requests

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

_EQL_START_RE = re.compile(
    r"^\s*(process|file|network|registry|dns|library|driver|any)\s+where\b",
    re.IGNORECASE,
)

_EQL_SEQUENCE_RE = re.compile(
    r"^\s*sequence\b",
    re.IGNORECASE,
)


def _detect_query_language(query_str: str) -> str:
    """Heuristic EQL/KQL detection. Returns 'eql' or 'kql'."""
    if _EQL_START_RE.match(query_str) or _EQL_SEQUENCE_RE.match(query_str):
        return "eql"

    return "kql"


def _raise_for_status(
    resp: requests.Response,
    context: str,
) -> None:
    if resp.status_code < 400:
        return

    message = (
        f"{context}: "
        f"{resp.status_code} "
        f"{resp.text[:200]}"
    )

    if resp.status_code in _RETRYABLE_STATUS_CODES:
        raise ConnectorTransientError(message)

    if 400 <= resp.status_code < 500:
        raise ConnectorPermanentError(message)

    raise ConnectorResponseError(message)


class ElasticConnector(BaseConnector):

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        self._base_url = config.credentials["base_url"].rstrip("/")

        self._index = (
            config.scope.get("index", "*")
            if config.scope
            else "*"
        )

        self._forced_language = (
            config.scope.get("language")
            if config.scope
            else None
        )

        self._session = requests.Session()

        self._session.headers.update(
            {
                "Authorization": (
                    f"ApiKey {config.credentials['api_key']}"
                ),
                "Content-Type": "application/json",
            }
        )

    def _query_fallback(
        self,
        error: Exception,
    ) -> List[Dict[str, Any]]:
        """
        Graceful degraded execution for temporary failures.

        Permanent errors remain visible to the caller.
        """

        if isinstance(error, ConnectorPermanentError):
            raise error

        return []

    def query(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        """
        Execute a read-only Elastic query through the centralized
        resilience framework.
        """

        language = (
            self._forced_language
            or _detect_query_language(query_str)
        )

        if language == "eql":
            operation = self._query_eql
        else:
            operation = self._query_kql

        return self.execute_with_resilience(
            operation,
            query_str,
            time_range,
            fallback=self._query_fallback,
        )

    def _query_eql(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        earliest, latest = time_range

        body = {
            "query": query_str,
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": earliest,
                        "lte": latest,
                    }
                }
            },
        }

        try:
            resp = self._session.post(
                f"{self._base_url}/{self._index}/_eql/search",
                json=body,
                timeout=30,
            )

        except (requests.ConnectionError, requests.Timeout) as exc:
            raise ConnectorTransientError(
                f"Could not reach Elastic (EQL): {exc}"
            ) from exc

        _raise_for_status(
            resp,
            "EQL search failed",
        )

        try:
            response_body = resp.json()
        except ValueError as exc:
            raise ConnectorResponseError(
                "Elastic returned invalid JSON for EQL search"
            ) from exc

        return self._extract_eql_hits(response_body)

    def _query_kql(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        earliest, latest = time_range

        body = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": query_str
                            }
                        }
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": earliest,
                                    "lte": latest,
                                }
                            }
                        }
                    ],
                }
            }
        }

        try:
            resp = self._session.post(
                f"{self._base_url}/{self._index}/_search",
                json=body,
                timeout=30,
            )

        except (requests.ConnectionError, requests.Timeout) as exc:
            raise ConnectorTransientError(
                f"Could not reach Elastic (KQL): {exc}"
            ) from exc

        _raise_for_status(
            resp,
            "KQL search failed",
        )

        try:
            response_body = resp.json()
        except ValueError as exc:
            raise ConnectorResponseError(
                "Elastic returned invalid JSON for KQL search"
            ) from exc

        return self._extract_search_hits(response_body)

    @staticmethod
    def _extract_eql_hits(
        response_body: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        events = (
            response_body
            .get("hits", {})
            .get("events", [])
        )

        return [
            event.get("_source", {})
            for event in events
        ]

    @staticmethod
    def _extract_search_hits(
        response_body: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        hits = (
            response_body
            .get("hits", {})
            .get("hits", [])
        )

        return [
            hit.get("_source", {})
            for hit in hits
        ]

    def poll(self) -> List[Dict[str, Any]]:
        """
        Pull events since the last poll.

        Polling reuses the resilient query path.
        """

        earliest = (
            "now-1h"
            if self._last_poll_ts is None
            else "now-5m"
        )

        results = self.query(
            "*",
            (earliest, "now"),
        )

        self._last_poll_ts = time.time()

        return results

    def validate_connection(self) -> bool:
        """
        Validate Elastic connectivity through centralized resilience.

        Temporary failures are retried. If retries are exhausted,
        the original transient error is propagated.

        Permanent authentication/configuration failures are also
        propagated to the caller.
        """

        return self.execute_with_resilience(
            self._validate_connection_remote,
            max_attempts=3,
        )

    def _validate_connection_remote(self) -> bool:
        try:
            resp = self._session.get(
                f"{self._base_url}/_cluster/health",
                timeout=5,
            )

        except (requests.ConnectionError, requests.Timeout) as exc:
            raise ConnectorTransientError(
                f"Could not reach Elastic: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise ConnectorPermanentError(
                "Elastic rejected the API key — check credentials"
            )

        if resp.status_code in _RETRYABLE_STATUS_CODES:
            raise ConnectorTransientError(
                f"Elastic health check returned "
                f"{resp.status_code}"
            )

        if resp.status_code >= 400:
            raise ConnectorPermanentError(
                f"Elastic health check returned "
                f"{resp.status_code}"
            )

        return resp.status_code == 200


ConnectorRegistry.register(
    "elastic",
    ElasticConnector,
)