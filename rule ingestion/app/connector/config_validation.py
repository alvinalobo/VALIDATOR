
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from app.connector.base_connector import ConnectorConfig

# Credential fields each vendor's connector needs to function.
# Add an entry here whenever a new connector is added to the framework.
REQUIRED_CREDENTIAL_FIELDS: Dict[str, List[str]] = {
    "splunk": ["host", "token"],
    "sentinel": ["workspace_id", "token"],
    "elastic": ["base_url", "api_key"],
    "qradar": ["base_url", "sec_token"],
    "crowdstrike": ["base_url", "client_id", "client_secret"],
}


class ConnectorConfigError(Exception):
    """Raised when a connector config fails validation. Carries the
    full list of problems in .errors so a caller (e.g. an API handler)
    can return all of them at once instead of one-at-a-time."""

    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def _validate_base_url(value: str, field_name: str) -> List[str]:
    """A base_url isn't valid just because it's a non-empty string —
    check it actually parses as an http(s) URL with a host."""
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        return [f"credentials.{field_name} must start with http:// or https:// (got '{value}')"]
    if not parsed.netloc:
        return [f"credentials.{field_name} is missing a host (got '{value}')"]
    return []


def validate_connector_config(config: ConnectorConfig) -> Tuple[bool, List[str]]:
    """
    Validate a ConnectorConfig. Returns (is_valid, errors) — never
    raises, so callers that want a soft check (e.g. a UI form)
    can use this directly. For a hard check that raises, use
    validate_connector_config_or_raise() below.

    Checks, in order:
      1. connector_id and product are non-empty
      2. vendor is one of the known/registered vendor names
      3. every credential field that vendor requires is present and non-empty
      4. any *_url credential field present is a well-formed http(s) URL
      5. scope, if provided, is a dict (not e.g. a string or list)
    """
    errors: List[str] = []

    if not (config.connector_id or "").strip():
        errors.append("connector_id is required and cannot be empty")

    if not (config.product or "").strip():
        errors.append("product is required and cannot be empty")

    vendor = (config.vendor or "").strip().lower()
    if vendor not in REQUIRED_CREDENTIAL_FIELDS:
        errors.append(
            f"Unknown vendor '{config.vendor}'. Supported vendors: "
            f"{', '.join(sorted(REQUIRED_CREDENTIAL_FIELDS))}"
        )
        # Can't check vendor-specific credential fields without knowing
        # the vendor, so stop here rather than producing confusing
        # follow-on errors about fields that don't even apply.
        return (len(errors) == 0), errors

    credentials = config.credentials or {}
    if not isinstance(credentials, dict):
        errors.append("credentials must be a dict/object")
        credentials = {}

    for field in REQUIRED_CREDENTIAL_FIELDS[vendor]:
        value = credentials.get(field)
        if value is None or not str(value).strip():
            errors.append(f"missing required credential field '{field}' for vendor '{vendor}'")

    for field, value in credentials.items():
        if field.endswith("url") and value:
            errors.extend(_validate_base_url(str(value), field))

    if config.scope is not None and not isinstance(config.scope, dict):
        errors.append("scope must be a dict/object if provided")

    return (len(errors) == 0), errors


def validate_connector_config_or_raise(config: ConnectorConfig) -> None:
    """Hard-check variant: raises ConnectorConfigError(errors) if invalid,
    returns None (silently) if valid. Use this at the actual
    registration boundary where an invalid config should hard-stop
    the request rather than being handled softly."""
    is_valid, errors = validate_connector_config(config)
    if not is_valid:
        raise ConnectorConfigError(errors)
