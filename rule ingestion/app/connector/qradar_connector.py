import time
import httpx
from typing import List, Dict, Any

from app.connector.base_connector import BaseConnector, ConnectorConfig, ConnectorRegistry


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
    """

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        self.base_url = self.config.credentials.get(
            "base_url", ""
        ).rstrip("/")

        self.sec_token = self.config.credentials.get("sec_token")

        self.is_mock = self.config.credentials.get(
            "mock", not bool(self.base_url)
        )

        self.verify_ssl = self.config.credentials.get(
            "verify_ssl", False
        )

        self.timeout = self.config.credentials.get(
            "timeout", 30.0
        )

        self.poll_interval = self.config.credentials.get(
            "poll_interval", 1.0
        )

        self.max_poll_attempts = self.config.credentials.get(
            "max_poll_attempts", 30
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

    def validate_connection(self) -> bool:
        """Verify QRadar credentials and API connectivity."""

        if self.is_mock:
            return True

        url = f"{self.base_url}/api/ariel/searches"

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=10.0
            ) as client:

                response = client.get(
                    url,
                    headers=self._get_headers()
                )

                return response.status_code == 200

        except Exception:
            return False

    def query(
        self,
        query_str: str,
        time_range: tuple = (None, None)
    ) -> List[Dict[str, Any]]:
        """
        Execute an AQL query through the QRadar Ariel API.

        Lifecycle:
        1. Create Ariel search
        2. Poll search status
        3. Retrieve results
        """

        if self.is_mock:
            return self._query_mock(query_str, time_range)

        if not query_str or not query_str.strip():
            return []

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=self.timeout
            ) as client:

                # 1. Create Ariel search
                search_url = f"{self.base_url}/api/ariel/searches"

                response = client.post(
                    search_url,
                    headers=self._get_headers(),
                    params={"query_expression": query_str}
                )

                if response.status_code not in (200, 201):
                    return []

                search_data = response.json()

                search_id = search_data.get("search_id")

                if not search_id:
                    return []

                # 2. Poll Ariel search
                status_url = (
                    f"{self.base_url}/api/ariel/searches/"
                    f"{search_id}"
                )

                completed = False

                for _ in range(self.max_poll_attempts):

                    status_response = client.get(
                        status_url,
                        headers=self._get_headers()
                    )

                    if status_response.status_code != 200:
                        return []

                    status_data = status_response.json()

                    status = status_data.get("status", "").upper()

                    if status == "COMPLETED":
                        completed = True
                        break

                    if status in ("ERROR", "FAILED"):
                        return []

                    time.sleep(self.poll_interval)

                if not completed:
                    return []

                # 3. Retrieve Ariel search results
                results_url = (
                    f"{self.base_url}/api/ariel/searches/"
                    f"{search_id}/results"
                )

                results_response = client.get(
                    results_url,
                    headers=self._get_headers()
                )

                if results_response.status_code != 200:
                    return []

                results_data = results_response.json()

                return results_data.get("events", [])

        except Exception:
            return []

    def poll(self) -> List[Dict[str, Any]]:
        """
        Pull new QRadar events since the last poll.

        Uses a five-minute polling window.
        """

        now = time.time()

        start_ts = self._last_poll_ts or (now - 300)

        # Convert timestamps into an AQL time range.
        aql = (
            "SELECT * FROM events "
            f"START {int(start_ts * 1000)} "
            f"STOP {int(now * 1000)}"
        )

        results = self.query(
            aql,
            time_range=(start_ts, now)
        )

        self._last_poll_ts = now

        return results

    def _query_mock(
        self,
        query_str: str,
        time_range: tuple
    ) -> List[Dict[str, Any]]:
        """Mock QRadar AQL execution for offline testing."""

        mock_events = [
            {
                "sourceip": "192.168.1.10",
                "destinationip": "10.0.0.10",
                "username": "admin",
                "eventname": "Successful Login",
                "qid": 5001
            },
            {
                "sourceip": "192.168.1.20",
                "destinationip": "10.0.0.20",
                "username": "user1",
                "eventname": "Failed Login",
                "qid": 5002
            }
        ]

        return mock_events


# Register QRadar Connector with the registry
ConnectorRegistry.register("qradar", QRadarConnector)