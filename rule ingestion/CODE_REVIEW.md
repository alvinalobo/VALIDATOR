# Code Review — Rule Ingestion Service & Connector Framework

Date: 2026-09-07
Scope: `rule ingestion/` (Rule Ingestion Service + Connector Framework), repo-root
connector files, and the CI setup.
Method: manual review of all service/connector code + execution of the full test
suite (48 tests) against the Connector Framework's mock SIEM HTTP server.

---

## 1. Test execution (before / after)

| Metric | Before | After |
|---|---|---|
| `pytest tests/` | 10 failed / 37 passed | **48 passed** (stable across 6+ consecutive runs) |
| Runtime | ~8.5 s (with real network calls) | ~3.2 s |
| `pytest app/connector/tests/` | n/a | **16 passed** |
| CI workflow | Located in a subdirectory — **never executed by GitHub** | Moved to repo root, paths fixed |

The Rule Ingestion Service integration tests
(`tests/test_connector_integrations.py`) previously could not run against the
Connector Framework at all:

- `test_elastic_integration` performed **real DNS lookups** against
  `elastic-sandbox.internal` (the mock patched `httpx.Client.send`, but the
  Elastic connector uses `requests`), failing with `getaddrinfo failed`.
- `test_qradar_integration` failed because the mock returned HTTP 201 for the
  GET validation call (201 ≠ 200).
- `test_crowdstrike_integration` crashed with `AttributeError` — the mock
  response lacked `raise_for_status()` and returned a list where the connector
  expected a dict.
- `tests/conftest.py` computed `PROJECT_ROOT` as `parents[3]`, which resolves
  to the Desktop folder instead of the project root, and tests imported
  `MOCK_SERVER_STATE` in a way that silently forked the state dict from the one
  the mock server used (counter assertions always read 0).

All of these are fixed; the tests now run against the in-process mock SIEM HTTP
server over real HTTP for all four connectors (Splunk, Elastic, QRadar,
CrowdStrike LogScale), sharing state through a `mock_server_state` fixture.

---

## 2. Findings

### Critical / High

1. **Venv committed to git (2,591 files).** `rule ingestion/app/connector/venv/`
   (a Python 3.12 virtualenv created on a different machine — it points at
   `C:\Users\rahul\...\python.exe`) was tracked in the repo, along with
   `__pycache__/*.pyc` files. The venv is broken on this machine, bloats the
   repo (~2,600 tracked files), and would be copied into Docker images.
   **Fixed:** untracked all of it (the `.gitignore` already covered these).

2. **CI workflow never ran.** GitHub only executes workflows from the repository
   root; `.github/workflows/ci.yml` lived inside `rule ingestion/`, so the
   "Python CI" job was dead. A prior commit ("Fix 16 critical issues: CI
   workflow…") had not addressed this.
   **Fixed:** moved to `.github/workflows/ci.yml` at the repo root with
   `working-directory: rule ingestion` for install/tests and `-f dockerfile`
   for the image build.

3. **Rules API was unreachable.** `app/main.py` only registered
   `connector_router` — the `/api/v2/rules/*` router (`app/api/rules.py`) was
   never included, so every rules endpoint returned FastAPI's route-not-found
   404. `tests/test_rule_deprecation.py` "passed" `test_rule_not_found`
   only because *every* rules route was 404.
   **Fixed:** `app.include_router(rules_router)` in `app/main.py`.

4. **Connector integration tests were not actually exercising the framework**
   (see §1). Rewrote to drive the real connectors over HTTP against the mock
   server.

### Medium

5. **CrowdStrike `validate_connection()` — unreachable code.** The method
   `return`s inside the `try`, and `except (httpx.HTTPError, ValueError)` —
   listed first — already catches `httpx.HTTPStatusError`/`RequestError`, so
   the three subsequent `except` branches (including a duplicated
   `except ValueError`) could never run. Connection validation silently
   returned `False` instead of distinguishing transient vs. permanent
   failures.
   **Fixed:** collapsed to a single reachable handler with an explanatory
   comment.

6. **Config validation vendor mismatch.** `config_validation.py` required
   `crowdstrike: [base_url, client_id, client_secret]`, but the connector
   registers as `crowdstrike_logscale` and needs `host` + `token`. Any config
   for the real CrowdStrike connector would fail `validate_connector_config`
   with "Unknown vendor" (or demand fields the connector never reads).
   **Fixed:** key renamed to `crowdstrike_logscale` with `["host", "token"]`.

7. **Splunk connector (packaged) issues:**
   - `base_url = f"{host}:{port}"` produced an invalid URL when the host was a
     bare hostname (no scheme) — `httpx` would raise `UnsupportedProtocol`.
     The standalone connector at the repo root handled `scheme` explicitly.
     **Fixed:** scheme-aware base URL.
   - No read-only guard. The standalone connector blocks mutating SPL commands
     (`outputlookup`, `collect`, `delete`, `script`, `map`); the packaged one
     allowed them despite the framework's READ-ONLY contract.
     **Fixed:** added the same blocklist.
   - `except Exception: return []` silently converted auth failures, network
     errors, and server errors into "no results" — dangerous for a validation
     service ("no evidence" vs. "query failed" are different outcomes).
     **Fixed:** raises `ConnectorPermanentError` (401/403, non-2xx, missing
     sid) / `ConnectorTransientError` (network), consistent with the Elastic
     connector and the `retry.py` taxonomy.

8. **QRadar connector:** same silent `return []` pattern on every failure path
   (dispatch, status poll, results). **Fixed:** typed error propagation.

9. **`register_connector` endpoint does arbitrary `importlib.import_module` of
   a client-supplied module name.** This is an unauthenticated dynamic import
   and registration path. Not exploitable for direct RCE, but importing
   arbitrary modules has side effects and the endpoint can shadow the registry.
   **Recommendation:** restrict `request.module` to the `app.connector.*`
   namespace (or drop dynamic registration in favor of `load_plugins()`).

### Low / Hygiene

10. **Plugin loader used `print()`** for registration diagnostics — noisy in
    tests and invisible to structured logging. **Fixed:** `logging`.

11. **`MOCK_SERVER_STATE` dual-module fork** in the tests: pytest loads
    `tests/conftest.py` under one module name while `from tests.conftest
    import MOCK_SERVER_STATE` imports a second copy, so the server and the
    tests read different dicts. **Fixed:** `mock_server_state` fixture injects
    the same object; resets are now non-destructive `update()` (a concurrent
    request can no longer observe a half-cleared dict).

12. **Single-threaded `HTTPServer` flakiness on Windows.** Under the full suite
    the mock server intermittently aborted connections
    (`ReadError: [WinError 10053]`) with the failing test varying run-to-run.
    **Fixed:** `ThreadingHTTPServer` in both conftest files; the suite now
    passes 6/6 consecutive full runs.

13. **Pydantic v2 deprecations:** `Field(min_items=…)` in
    `app/models/rule_models.py` (use `min_length`), and `datetime.utcnow()`
    default factories. Minor; left as-is to avoid churn — worth a follow-up.

14. **Dead / duplicate code at the repo root:** `baseconnector.py` is a
    Sentinel connector mislabeled as "base connector" that imports
    `from app.base_connector import …` — a module that does not exist — so it
    cannot even be imported. The root `splunk_connector.py` is a second,
    self-contained connector framework duplicating
    `rule ingestion/app/connector/*`. Recommend deleting `baseconnector.py`
    and consolidating on the packaged framework.

15. **No `.dockerignore`** — a `docker build` would copy the (now untracked,
    but on-disk) venv into the image. **Fixed:** added `rule ingestion/.dockerignore`.

16. **`rules.py` ingestion notes:** `clone_repo()` clones an arbitrary
    user-supplied URL (GitPython) and hard-resets local clones; the
    `discover_rule_files` walk is fine but should be bounded. No auth on the
    API (acceptable for an internal service, but worth flagging if this ever
    faces the network).

---

## 3. What was changed in this pass

| File | Change |
|---|---|
| `tests/conftest.py` | Fixed `PROJECT_ROOT` (parents[3]→parents[1]); added `mock_server_state` fixture; CrowdStrike mock endpoints; QRadar handler ordering; `ThreadingHTTPServer`; non-destructive reset |
| `tests/test_connector_integrations.py` | Rewritten to run all four connectors over the mock HTTP server with shared state |
| `tests/test_connectors.py` | Uses `mock_server_state` fixture; `monkeypatch` for backoff sleeps |
| `app/connector/tests/conftest.py` | Added project-root sys.path bootstrap; `mock_server_state` fixture; `ThreadingHTTPServer`; non-destructive reset |
| `app/connector/tests/test_connectors.py` | Same fixture fixes as the root test copy |
| `app/main.py` | Registered the rules router |
| `app/connector/config_validation.py` | Corrected CrowdStrike vendor key + required fields |
| `app/connector/crowdstrike_logscale_connector.py` | Removed unreachable except branches; defensive job-id extraction |
| `app/connector/splunk_connector.py` | Scheme-aware base URL; read-only blocklist; typed error propagation |
| `app/connector/qradar_connector.py` | Typed error propagation instead of silent `[]` |
| `app/connector/plugin_loader.py` | Logging instead of `print` |
| `.github/workflows/ci.yml` (moved) | Repo-root CI with corrected paths |
| `rule ingestion/.dockerignore` | Added |
| `rule ingestion/.gitignore` | Added `repositories/`, `.cloned_repos/` |
| git index | Untracked committed `venv/` (2,591 files), `__pycache__/*.pyc`, `app/python`, broken `repositories/sigma` gitlink |

## 4. Recommended follow-ups

- Delete the broken `baseconnector.py` at the repo root and consolidate the two
  connector frameworks into `app/connector/`.
- Add rate limiting to the packaged Splunk/QRadar connectors (the standalone
  Splunk connector had a `RateLimiter` the packaged one lacks).
- Restrict `register_connector` to `app.connector.*` modules.
- Replace `min_items` with `min_length` and move off `datetime.utcnow`.
- Point the CI workflow at a real (or containerized) SIEM for true
  end-to-end validation in addition to the mock server.