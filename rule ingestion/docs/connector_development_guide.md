# Connector Development Guide

## 1. Purpose

This guide explains how to add, configure, register, test, and troubleshoot a connector in the Rule Ingestion Service Connector Framework.

A connector is a `BaseConnector` implementation that provides a common interface for querying an external SIEM/security platform. The current framework standardizes three operations:

- `query(query_str, time_range)` — execute a read-only detection/query operation.
- `poll()` — pull new events since the connector's previous poll.
- `validate_connection()` — verify that the configured connector can reach and authenticate to its remote platform.

Every connector receives a `ConnectorConfig`, uses the shared resilience layer, and is registered in `ConnectorRegistry`.

---

## 2. Framework Architecture

```text
                         Rule Ingestion Service
                                  |
                                  v
                         +------------------+
                         |  BaseConnector   |
                         |      (ABC)       |
                         +--------+---------+
                                  |
              +-------------------+-------------------+
              |                   |                   |
              v                   v                   v
        ConnectorConfig     ConnectorResilience   ConnectorRegistry
              |                   |                   |
              |             +-----+-----+             |
              |             |     |     |             |
              |           Retry Circuit Fallback      |
              |          Breaker Breaker              |
              |                                     |
              +-------------------+-----------------+
                                  |
            +---------------------+----------------------+
            |            |            |          |       |
            v            v            v          v       v
         Splunk      Sentinel      Elastic    QRadar  CrowdStrike
                                                      LogScale
```

### Main framework components

| Component | Responsibility |
|---|---|
| `BaseConnector` | Common abstract connector interface and resilience helpers |
| `ConnectorConfig` | Pydantic configuration model passed to every connector |
| `ConnectorRegistry` | Maps a vendor key to a connector class |
| `ConnectorResilience` | Centralized retry, circuit breaker, and fallback execution |
| `with_retry` | Retries only `ConnectorTransientError` using exponential backoff and jitter |
| `CircuitBreaker` | Prevents repeated calls while a connector is in an `OPEN` state |
| `config_validation.py` | Validates connector IDs, vendors, required credentials, URLs, and scope |

---

## 3. Current BaseConnector Contract

All connector implementations inherit from:

```python
from app.connector.base_connector import BaseConnector, ConnectorConfig
```

The current configuration model is:

```python
class ConnectorConfig(BaseModel):
    connector_id: str
    vendor: str
    product: str
    credentials: Dict[str, Any] = Field(default_factory=dict)
    scope: Dict[str, Any] = Field(default_factory=dict)
```

### Configuration fields

| Field | Type | Required | Purpose |
|---|---|---:|---|
| `connector_id` | `str` | Yes | Unique ID for a configured connector instance |
| `vendor` | `str` | Yes | Framework vendor key, such as `splunk`, `elastic`, or `qradar` |
| `product` | `str` | Yes | Product/SIEM name for the connector instance |
| `credentials` | `dict` | No | Authentication and endpoint information |
| `scope` | `dict` | No | Connector-specific query scope, such as an Elastic index or LogScale repository |

Example:

```python
config = ConnectorConfig(
    connector_id="elastic-sec-prod",
    vendor="elastic",
    product="elastic_security",
    credentials={
        "base_url": "https://elastic.example.com",
        "api_key": "secret-api-key",
    },
    scope={
        "index": "logs-*",
    },
)
```

### Important

Endpoint and authentication values are stored inside `credentials`; they are **not** top-level `ConnectorConfig.host`, `rate_limit`, or `timeout` fields.

Connector-specific optional values such as `timeout`, `verify_ssl`, `page_size`, or polling settings are read by the relevant connector from `credentials` where supported.

---

## 4. Required Connector Methods

A new connector must implement all three abstract methods from `BaseConnector`.

### 4.1 `query()`

```python
def query(
    self,
    query_str: str,
    time_range: tuple,
) -> List[Dict[str, Any]]:
    """Execute a read-only query and return raw results."""
```

Use this method for detection/query execution.

The exact query language is connector-specific:

- Splunk uses SPL.
- Microsoft Sentinel uses KQL through its current Graph Security API implementation.
- Elastic supports KQL and EQL.
- IBM QRadar uses AQL.
- CrowdStrike LogScale uses LQL.

`time_range` is a two-value tuple when the connector requires a time window. Some connectors provide a default such as `(None, None)`.

A query must be read-only. Connectors are not intended to make destructive changes to the remote SIEM.

### 4.2 `poll()`

```python
def poll(self) -> List[Dict[str, Any]]:
    """Pull new events since the last poll."""
```

Polling is stateful at connector-instance level. `BaseConnector` provides:

```python
self._last_poll_ts
```

Connectors that support timestamp-based polling update this value after a successful poll.

Examples:

- Splunk polls from the last poll timestamp, or a short initial lookback.
- Elastic uses a default recent window for its first poll and a shorter lookback for subsequent polls.
- CrowdStrike LogScale polls the most recently created query job.
- Sentinel and QRadar currently expose query/validation behavior but do not define a `poll()` method in their source files.

When implementing a new connector, follow the `BaseConnector` contract and provide `poll()`.

### 4.3 `validate_connection()`

```python
def validate_connection(self) -> bool:
    """Verify credentials and remote connectivity."""
```

This must perform a read-only connectivity/authentication check.

A connector may use the resilience layer and/or return `False` for a degraded validation path depending on its implementation. Authentication/configuration errors should not be mislabeled as transient errors.

---

## 5. Create a New Connector

Create a module under:

```text
app/connector/
```

For example:

```text
app/connector/my_siem_connector.py
```

The module should contain a `BaseConnector` subclass.

Basic structure:

```python
from typing import Any, Dict, List

from app.connector.base_connector import (
    BaseConnector,
    ConnectorConfig,
)
from app.connector.exceptions import (
    ConnectorPermanentError,
    ConnectorTransientError,
)


class MySiemConnector(BaseConnector):
    """Connector for MySIEM."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

    def query(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        # Implement the remote read-only query.
        pass

    def poll(self) -> List[Dict[str, Any]]:
        # Implement incremental/event polling.
        pass

    def validate_connection(self) -> bool:
        # Implement a read-only health/authentication check.
        pass
```

Do not add a separate `CONNECTOR_TYPE`/`CONNECTOR_TYPE` configuration field to `ConnectorConfig`. The framework identifies the registered connector by its registry vendor key.

---

## 6. Connector Registry

`ConnectorRegistry` stores connector classes by vendor:

```python
ConnectorRegistry.register("my_siem", MySiemConnector)
```

A connector can then be retrieved with:

```python
connector_cls = ConnectorRegistry.get("my_siem")

connector = connector_cls(config)
```

Registry keys are normalized to lowercase.

Looking up an unregistered vendor raises `KeyError`.

---

## 7. Plugin Loader

`app/connector/plugin_loader.py` dynamically discovers connector modules under `app.connector`.

The loader:

1. Imports the `app.connector` package.
2. Iterates through modules using `pkgutil`.
3. Ignores framework modules such as `base_connector`, `exceptions`, and `plugin_loader`.
4. Imports each connector module.
5. Finds classes that inherit from `BaseConnector`.
6. Derives the vendor key from the module name by removing `_connector`.
7. Registers the connector with `ConnectorRegistry`.

For example:

```text
splunk_connector.py
        |
        v
vendor = "splunk"
```

and:

```text
crowdstrike_logscale_connector.py
        |
        v
vendor = "crowdstrike_logscale"
```

The application calls `load_plugins()` during startup before the connector router is used.

### Practical rule

For automatic discovery, name the module using:

```text
<vendor>_connector.py
```

and place the `BaseConnector` subclass in that module.

---

## 8. Configuration Validation

`app/connector/config_validation.py` defines the required credential fields for known vendors.

Current required fields:

| Vendor | Required credentials |
|---|---|
| `splunk` | `host`, `token` |
| `sentinel` | `workspace_id`, `token` |
| `elastic` | `base_url`, `api_key` |
| `qradar` | `base_url`, `sec_token` |
| `crowdstrike` | `base_url`, `client_id`, `client_secret` |

The validator also checks:

- `connector_id` is not empty.
- `product` is not empty.
- `vendor` is known.
- required credential fields are present and non-empty.
- credential fields ending in `url` contain a valid `http://` or `https://` URL with a host.
- `scope`, when supplied, is a dictionary.

Use:

```python
from app.connector.config_validation import (
    validate_connector_config,
    validate_connector_config_or_raise,
)
```

`validate_connector_config()` returns:

```python
(is_valid, errors)
```

`validate_connector_config_or_raise()` raises `ConnectorConfigError` when validation fails.

### Adding a new vendor

When a new connector needs framework-level credential validation, add its required credential fields to:

```python
REQUIRED_CREDENTIAL_FIELDS
```

Example:

```python
REQUIRED_CREDENTIAL_FIELDS = {
    # existing entries ...
    "my_siem": ["base_url", "api_key"],
}
```

The exact fields must match what the connector actually reads from `config.credentials`.

---

## 9. Error Handling

Use the connector exception hierarchy from:

```text
app/connector/exceptions.py
```

### Exception categories

| Exception | Meaning |
|---|---|
| `ConnectorError` | Base connector exception |
| `ConnectorTransientError` | Temporary failure that may succeed when retried |
| `ConnectorPermanentError` | Failure that normally should not be retried |
| `ConnectorTimeoutError` | Timeout; subclass of transient error |
| `ConnectorConnectionError` | Connection failure; subclass of transient error |
| `ConnectorRateLimitError` | Rate limit; subclass of transient error |
| `ConnectorServerError` | HTTP 5xx/server failure; subclass of transient error |
| `ConnectorAuthenticationError` | Authentication/authorization failure |
| `ConnectorBadRequestError` | Invalid request |
| `ConnectorNotFoundError` | Missing resource/endpoint |
| `ConnectorConfigurationError` | Invalid connector configuration |
| `ConnectorResponseError` | Unexpected or invalid response |
| `ConnectorFallbackError` | Fallback itself failed |

### Rule of thumb

Use transient exceptions for conditions such as:

- network interruption
- timeout
- rate limiting
- server-side 5xx failures

Use permanent exceptions for:

- invalid credentials
- 400/401/403/404 conditions when they represent a permanent request/configuration problem
- invalid connector configuration
- malformed/unexpected responses
- invalid queries that the remote service will not accept

Do not wrap every exception as transient; incorrect classification can cause unnecessary retries.

---

## 10. Resilience Framework

Every `BaseConnector` instance receives its own:

```python
self.resilience = ConnectorResilience()
```

Operations can be executed through:

```python
self.execute_with_resilience(
    operation,
    ...,
    fallback=...
)
```

The execution flow is:

```text
Connector operation
       |
       v
CircuitBreaker
       |
       v
with_retry()
       |
       +---- transient error ----> retry with backoff/jitter
       |
       v
Operation result
       |
       +---- failure after allowed attempts ----> fallback (if defined)
```

### Retry

`with_retry()` retries only:

```python
ConnectorTransientError
```

The default settings in `ConnectorResilience` are:

| Setting | Default |
|---|---:|
| Circuit failure threshold | 5 |
| Circuit recovery timeout | 30 seconds |
| Max retry attempts | 4 |
| Base retry delay | 1 second |
| Maximum retry delay | 30 seconds |
| Jitter | 25% |

The retry delay uses exponential backoff with a maximum delay and random jitter.

### Circuit breaker

`CircuitBreaker` has three states:

```text
CLOSED
  |
  | failure threshold reached
  v
OPEN
  |
  | cooldown elapsed
  v
HALF_OPEN
  |
  +---- success ----> CLOSED
  |
  +---- failure ----> OPEN
```

When the circuit is `OPEN`, calls fail fast until the cooldown has elapsed.

The connector exposes:

```python
connector.circuit_state
connector.circuit_failure_count
```

and can manually reset the breaker with:

```python
connector.reset_resilience()
```

### Fallbacks

Fallbacks are optional and should return a safe degraded result.

Example:

```python
return self.execute_with_resilience(
    self._query_remote,
    query_str,
    time_range,
    fallback=self._query_fallback,
)
```

Do not hide permanent configuration/authentication problems behind a fallback unless that behavior is explicitly intended by the connector contract.

---

## 11. HTTP and Response Handling

For real integrations:

- Set a finite HTTP timeout.
- Call `raise_for_status()` where appropriate.
- Convert network/timeouts/5xx/rate-limit failures to transient connector exceptions.
- Convert authentication or invalid-request responses to permanent connector exceptions where appropriate.
- Validate the shape of JSON returned by the remote API.
- Raise `ConnectorResponseError` when the response is syntactically valid JSON but does not match the expected structure.
- Never log credentials, tokens, client secrets, or API keys.

---

## 12. Connector-Specific Configuration

The following connector implementations are currently included in the project.

### Splunk

Module:

```text
app/connector/splunk_connector.py
```

Registry vendor:

```text
splunk
```

Query language:

```text
SPL
```

Credentials used by the implementation include:

```python
{
    "host": "https://splunk.example.com",
    "port": 8089,
    "token": "...",
    # or username/password depending on connector behavior
    "username": "...",
    "password": "...",
    "mock": False,
    "verify_ssl": True,
}
```

The test suite also uses mock mode:

```python
credentials={"mock": True}
```

### Microsoft Sentinel

Module:

```text
app/connector/sentinel_connector.py
```

Registry vendor:

```text
sentinel
```

Query language:

```text
KQL
```

The implementation reads values including:

```python
{
    "tenant_id": "...",
    "client_id": "...",
    "client_secret": "...",
    "workspace_id": "...",
    "access_token": "...",
    "mock": False,
    "verify_ssl": True,
    "timeout": 30.0,
    "page_size": 100,
}
```

### Elastic Security

Module:

```text
app/connector/elastic_connector.py
```

Registry vendor:

```text
elastic
```

The connector supports:

```text
KQL
EQL
```

Credentials:

```python
{
    "base_url": "https://elastic.example.com",
    "api_key": "...",
}
```

Optional scope:

```python
{
    "index": "logs-*",
    "language": "kql",
}
```

If no language is forced through scope, the connector detects KQL/EQL from the query string.

### IBM QRadar

Module:

```text
app/connector/qradar_connector.py
```

Registry vendor:

```text
qradar
```

Query language:

```text
AQL
```

Credentials include:

```python
{
    "base_url": "https://qradar.example.com",
    "sec_token": "...",
    "mock": False,
    "verify_ssl": True,
    "timeout": 30.0,
    "poll_interval": ...,
    "max_poll_attempts": ...,
}
```

The query lifecycle is handled internally by the connector:

```text
Create Ariel search
       |
       v
Poll search status
       |
       v
Retrieve results
```

### CrowdStrike LogScale

Module:

```text
app/connector/crowdstrike_logscale_connector.py
```

Registry vendor:

```text
crowdstrike_logscale
```

Query language:

```text
LQL
```

Credentials include:

```python
{
    "host": "https://...",
    "token": "...",
}
```

Scope includes the LogScale repository, for example:

```python
{
    "repository": "default",
}
```

The connector stores the latest query job ID internally and `poll()` retrieves the latest job's results.

---

## 13. Runtime Registration API

The connector API is defined in:

```text
app/api/connector_routes.py
```

The router prefix is:

```text
/api/v2/connectors
```

### Register a connector

```http
POST /api/v2/connectors/register
Content-Type: application/json
```

Request body:

```json
{
  "vendor": "my_siem",
  "module": "app.connector.my_siem_connector",
  "class_name": "MySiemConnector"
}
```

The registration route:

1. Checks whether the vendor is already registered.
2. Imports the specified module.
3. Resolves the requested class.
4. Registers the class in `ConnectorRegistry`.

A duplicate vendor returns HTTP `409`.

A missing module or class returns HTTP `404`.

### List registered connectors

```http
GET /api/v2/connectors/registered
```

Response:

```json
{
  "count": 5,
  "vendors": [
    "splunk",
    "sentinel",
    "elastic",
    "qradar",
    "crowdstrike_logscale"
  ]
}
```

The exact list depends on the connectors successfully loaded at startup.

---

## 14. Health Monitoring API

Health monitoring is exposed by the same connector router.

### Register health monitoring

```http
POST /api/v2/connectors/health/{connector_id}/register?vendor=my_siem&product=my_product
```

### Read one connector's health

```http
GET /api/v2/connectors/health/{connector_id}
```

Returns the current `ConnectorHealthStatus` when the connector is known to the health monitor.

### Read all connector health

```http
GET /api/v2/connectors/health
```

### Record a query result

```http
POST /api/v2/connectors/health/{connector_id}/query
Content-Type: application/json
```

Example:

```json
{
  "latency": 0.42,
  "success": true
}
```

`latency` is measured in seconds and cannot be negative.

### Record connector availability

```http
POST /api/v2/connectors/health/{connector_id}/connection
Content-Type: application/json
```

Example:

```json
{
  "available": true
}
```

These endpoints update the framework's health monitor; they do not replace `validate_connection()`.

---

## 15. Application Startup

The application entrypoint is:

```text
app/main.py
```

At startup it:

1. Creates the FastAPI application.
2. Calls `load_plugins()`.
3. Includes the connector router.

The connector API therefore becomes available under:

```text
/api/v2/connectors
```

The application also exposes:

```text
GET /
GET /health
```

---

## 16. Testing a New Connector

Place connector-specific tests under the project's test structure. Existing integration tests are under:

```text
tests/
```

and connector resilience tests are under:

```text
app/connector/tests/
```

A useful unit/integration test set should cover:

1. successful connection validation;
2. authentication or validation failure;
3. successful query;
4. empty query validation when applicable;
5. transient HTTP/network failure;
6. retry behavior;
7. retry exhaustion;
8. permanent error behavior;
9. fallback behavior when implemented;
10. polling behavior;
11. registry registration;
12. response-shape validation;
13. mock mode where the connector supports it.

### Existing test pattern

```python
from app.connector.base_connector import ConnectorConfig
from app.connector.my_siem_connector import MySiemConnector

config = ConnectorConfig(
    connector_id="my-siem-test",
    vendor="my_siem",
    product="my_siem",
    credentials={
        "base_url": "https://my-siem.example.com",
        "api_key": "test-key",
    },
)

connector = MySiemConnector(config)
```

For unit tests, mock external HTTP calls rather than contacting a production SIEM.

Run the test suite from the Rule Ingestion Service directory with:

```bash
pytest -v
```

Or run connector-specific tests, for example:

```bash
pytest app/connector/tests -v
pytest tests/test_connectors.py -v
pytest tests/test_connector_integrations.py -v
```

Use the test paths that exist in the project checkout.

---

## 17. Connector Development Checklist

Before submitting a new connector:

- [ ] Create `<vendor>_connector.py` under `app/connector/`.
- [ ] Inherit from `BaseConnector`.
- [ ] Implement `query(query_str, time_range)`.
- [ ] Implement `poll()`.
- [ ] Implement `validate_connection()`.
- [ ] Use `ConnectorConfig` fields correctly.
- [ ] Keep endpoint/authentication data inside `credentials`.
- [ ] Use `scope` only for connector-specific scope/configuration.
- [ ] Classify failures with the connector exception hierarchy.
- [ ] Route remote operations through `execute_with_resilience()` when appropriate.
- [ ] Add required vendor credentials to `REQUIRED_CREDENTIAL_FIELDS`.
- [ ] Ensure the module name produces the intended plugin-loader vendor key.
- [ ] Add tests using mocks for remote HTTP behavior.
- [ ] Test retryable and non-retryable failures.
- [ ] Test response validation.
- [ ] Verify `ConnectorRegistry.get("<vendor>")`.
- [ ] Verify application startup loads the connector.
- [ ] Confirm credentials and secrets are not written to logs.

---

## 18. Troubleshooting

### Connector is not registered

Check:

```text
app/connector/<vendor>_connector.py
```

and verify that the module contains a class inheriting from `BaseConnector`.

Also check application startup output from `load_plugins()`.

### `ConnectorRegistry.get()` raises `KeyError`

Verify the vendor key used in the lookup matches the registered key. Registry keys are lowercased.

For auto-discovery, remember that:

```text
crowdstrike_logscale_connector.py
```

becomes:

```text
crowdstrike_logscale
```

### Configuration validation fails

Check:

- `connector_id`
- `product`
- supported `vendor`
- required credential field names
- URL format for URL credential fields
- `scope` type

### Queries retry unexpectedly

Inspect whether the connector is raising `ConnectorTransientError` for a condition that should be permanent.

### Queries never retry

Check that the failure is raised as `ConnectorTransientError` rather than a generic exception.

### Circuit is OPEN

Use:

```python
connector.circuit_state
connector.circuit_failure_count
```

and reset when appropriate:

```python
connector.reset_resilience()
```

Do not use manual resets as a substitute for fixing a persistent connector failure.

---

## 19. Connector Specification Contract

The repository also contains a frozen connector specification under:

```text
contracts/connector specification/
```

The current specification defines metadata including:

- connector name
- connector version
- SIEM platform
- supported query language
- input rule format
- output format
- authentication

The frozen schema currently requires Sigma as the input rule format and defines authentication values such as API Key, OAuth, and Username/Password.

When creating or documenting a connector, keep its implementation and any connector-specification metadata consistent with this contract.

---

## 20. Reference Implementations

Use these existing connectors as implementation references:

| Vendor key | Module | Platform | Query language |
|---|---|---|---|
| `splunk` | `splunk_connector.py` | Splunk | SPL |
| `sentinel` | `sentinel_connector.py` | Microsoft Sentinel | KQL |
| `elastic` | `elastic_connector.py` | Elastic Security | KQL / EQL |
| `qradar` | `qradar_connector.py` | IBM QRadar | AQL |
| `crowdstrike_logscale` | `crowdstrike_logscale_connector.py` | CrowdStrike LogScale | LQL |

The source implementations are the authority for connector-specific credential names, query behavior, polling behavior, and remote API details.
