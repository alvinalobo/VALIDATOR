import os
import sys
import pytest

# Configure python path to root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app.connector.base_connector import ConnectorConfig
from app.connector.config_validation import validate_connector_config, ConnectorConfigError

def test_config_validation_requires_mandatory_credentials():
    """Verify that missing mandatory credential fields per vendor are flagged as errors."""
    # Splunk missing 'token'
    invalid_splunk_config = ConnectorConfig(
        connector_id="splunk-test",
        vendor="splunk",
        product="siem",
        credentials={"host": "https://splunk.internal:8089"}
    )
    is_valid, errors = validate_connector_config(invalid_splunk_config)
    assert is_valid is False
    assert any("token" in err for err in errors)

def test_config_validation_enforces_https_urls():
    """Verify that malformed base_url credentials are rejected."""
    invalid_url_config = ConnectorConfig(
        connector_id="elastic-test",
        vendor="elastic",
        product="siem",
        credentials={"base_url": "invalid-url-string", "api_key": "secret"}
    )
    is_valid, errors = validate_connector_config(invalid_url_config)
    assert is_valid is False
    assert any("must start with http://" in err or "http://" in err for err in errors)

def test_valid_connector_credentials_pass_audit():
    """Verify that complete valid credentials pass configuration security validation."""
    valid_config = ConnectorConfig(
        connector_id="qradar-test",
        vendor="qradar",
        product="siem",
        credentials={"base_url": "https://qradar.internal", "sec_token": "valid-sec-token-123"}
    )
    is_valid, errors = validate_connector_config(valid_config)
    assert is_valid is True
    assert len(errors) == 0
