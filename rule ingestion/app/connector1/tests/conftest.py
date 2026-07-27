import time
import socket
import threading
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest

# Global mock server state that tests can modify
MOCK_SERVER_STATE = {
    "splunk_dispatch_status_calls": 0,
    "splunk_dispatch_state": "DONE",
    "elastic_health_status": 200,
    "elastic_health_calls": 0,
    "elastic_search_status": 200,
    "elastic_search_response": {
        "hits": {
            "hits": [{"_source": {"event": "kql_test"}}]
        }
    },
    "elastic_eql_status": 200,
    "elastic_eql_response": {
        "hits": {
            "events": [{"_source": {"event": "eql_test"}}]
        }
    },
    "splunk_results_response": {
        "results": [{"_raw": "splunk_test"}]
    }
}

class MockSIEMRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging to keep pytest output clean

    def do_GET(self):
        # Splunk Auth validation
        if "services/authentication/current-context" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"username": "admin"}).encode("utf-8"))
            return

        # Splunk Job Poll status
        if "services/search/jobs/" in self.path and "/results" not in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            MOCK_SERVER_STATE["splunk_dispatch_status_calls"] += 1
            self.wfile.write(json.dumps({
                "entry": [{"content": {"dispatchState": MOCK_SERVER_STATE["splunk_dispatch_state"]}}]
            }).encode("utf-8"))
            return

        # Splunk Job Poll results
        if "services/search/jobs/" in self.path and "/results" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(MOCK_SERVER_STATE["splunk_results_response"]).encode("utf-8"))
            return

        # Elastic Health Check (including retry testing)
        if "_cluster/health" in self.path:
            status = MOCK_SERVER_STATE["elastic_health_status"]
            MOCK_SERVER_STATE["elastic_health_calls"] += 1
            
            if isinstance(status, list):
                # Retrieve current status from list to simulate transient errors recovering
                idx = min(MOCK_SERVER_STATE["elastic_health_calls"] - 1, len(status) - 1)
                curr_status = status[idx]
            else:
                curr_status = status

            self.send_response(curr_status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if curr_status == 200:
                self.wfile.write(json.dumps({"status": "green"}).encode("utf-8"))
            else:
                self.wfile.write(json.dumps({"error": f"HTTP {curr_status} error"}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        # Splunk Dispatch Job
        if "services/search/jobs" in self.path:
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"sid": "job_12345"}).encode("utf-8"))
            return

        # Elastic Search
        if "/_search" in self.path:
            status = MOCK_SERVER_STATE["elastic_search_status"]
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(MOCK_SERVER_STATE["elastic_search_response"]).encode("utf-8"))
            return

        # Elastic EQL Search
        if "/_eql/search" in self.path:
            status = MOCK_SERVER_STATE["elastic_eql_status"]
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(MOCK_SERVER_STATE["elastic_eql_response"]).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="session")
def mock_server_url():
    port = get_free_port()
    server = HTTPServer(("127.0.0.1", port), MockSIEMRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()

@pytest.fixture(autouse=True)
def reset_mock_state():
    """Reset global mock state before each test."""
    global MOCK_SERVER_STATE
    MOCK_SERVER_STATE.clear()
    MOCK_SERVER_STATE.update({
        "splunk_dispatch_status_calls": 0,
        "splunk_dispatch_state": "DONE",
        "elastic_health_status": 200,
        "elastic_health_calls": 0,
        "elastic_search_status": 200,
        "elastic_search_response": {
            "hits": {
                "hits": [{"_source": {"event": "kql_test"}}]
            }
        },
        "elastic_eql_status": 200,
        "elastic_eql_response": {
            "hits": {
                "events": [{"_source": {"event": "eql_test"}}]
            }
        },
        "splunk_results_response": {
            "results": [{"_raw": "splunk_test"}]
        }
    })
