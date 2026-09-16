# Rule Ingestion Service — API Documentation

Module 1 of **The Validator**. Ingests detection rules (Sigma + KQL) from Git
repositories, parses and validates them, keeps a content-addressed history of
every rule revision, and exposes a plugin-based SIEM connector framework.

Generated reference (interactive):

| Document | URL |
|---|---|
| Swagger UI | `/docs` |
| ReDoc | `/redoc` |
| OpenAPI JSON | `/openapi.json` |

---

## 1. Quick start

```bash
cd "rule ingestion"

# Install dependencies
pip install -r requirements.txt

# Run the service
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Run the test suite
pytest

# Apply database migrations
alembic upgrade head
```

Docker:

```bash
docker build -f Dockerfile -t rule-ingestion .
docker run -p 8000:8000 rule-ingestion
```

---

## 2. Configuration

All configuration is environment-driven; no credentials are committed.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | No | `sqlite:///./rule_ingestion.db` | SQLAlchemy URL used by Alembic migrations. Set to the PostgreSQL instance in deployed environments. |
| `CONNECTOR_ENCRYPTION_KEY` | Yes, to use `CredentialManager` | — | Fernet key used to encrypt SIEM connector credentials at rest. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. |

---

## 3. Endpoint reference

### 3.1 Rules — `/api/v2/rules`

#### `POST /api/v2/rules/ingest`

Clone (or, for a local path, read in place) a Git repository, discover rule
files, parse and validate them, and record each revision in the version store.

**Request — `RuleIngestRequest`**

| Field | Type | Default | Notes |
|---|---|---|---|
| `repo_url` | string | required | `http(s)` Git URL **or** an existing local directory path. Local paths are supported for air-gapped ingestion and the integration suite. |
| `branch` | string | `"main"` | Branch, tag or commit hash. |
| `rule_types` | list of enum | `["sigma", "kql"]` | Any of `sigma`, `kql`, `yara`. |
| `include_validation` | bool | `true` | Run syntax validation during ingestion. |
| `tags` | list of string | `null` | Tags applied to every ingested rule. |

```bash
curl -X POST http://localhost:8000/api/v2/rules/ingest \
  -H 'Content-Type: application/json' \
  -d '{"repo_url": "https://github.com/SigmaHQ/sigma.git", "branch": "main"}'
```

Returns `List[ParsedRule]`. Repositories managed by `clone_repo` are cloned
shallow (`depth=1`, `single_branch=True`) and cached under `.cloned_repos/`.

#### `GET /api/v2/rules/search`

Search, filter, sort and paginate ingested rules.

| Query param | Type | Default | Notes |
|---|---|---|---|
| `q` | string | `""` | Matches title, description and tags. |
| `status` | string | — | `active` or `deprecated`. Anything else → `400`. |
| `severity` | string | — | `low`, `medium`, `high`, `critical`. |
| `mitre_technique` | string | — | Exact technique id, e.g. `T1059`. |
| `rule_format` | string | — | `sigma`, `kql`, `yara`. Invalid → `400`. |
| `page` | int ≥ 1 | `1` | |
| `page_size` | int 1–100 | `20` | |
| `sort_by` | string | `created_at` | `created_at`, `updated_at`, `title`. |
| `sort_order` | string | `desc` | `asc` or `desc`. |
| `paginated` | bool | `false` | `true` returns the pagination envelope; `false` returns a bare list. |

Pagination metadata is always returned as headers, regardless of `paginated`:
`X-Total-Count`, `X-Page`, `X-Page-Size`, `X-Total-Pages`, `X-Has-Next`,
`X-Has-Prev`.

```bash
curl 'http://localhost:8000/api/v2/rules/search?severity=critical&paginated=true'
```

#### `GET /api/v2/rules/{rule_id}`

Returns the stored `ParsedRule`, or `404`.

#### `POST /api/v2/rules/{rule_id}/deprecate`

Retires a rule. Sets `is_active = false` and marks the current version
`deprecated`, **without deleting any history** — superseded content hashes stay
resolvable so historical verdicts remain reproducible. Reports
`dependent_count` and a `warning` when validation runs still reference the rule
(deprecation is deliberately not blocked, since blocking would itself break
those runs).

#### `POST /api/v2/rules/{rule_id}/restore`

Reinstates a deprecated rule; history is untouched.

#### `GET /api/v2/rules/{rule_id}/versions`

Full content-addressed history:

```json
{
  "rule_id": "rule-sigma-01",
  "version_count": 2,
  "current_version": 2,
  "current_content_hash": "b2...",
  "status": "active",
  "versions": [ { "version": 1, "is_latest": false, "...": "..." } ]
}
```

#### `GET /api/v2/rules/{rule_id}/versions/{version}`

Resolves one historical revision by version number. `404` if it never existed.

#### `GET /api/v2/rules/{rule_id}/dependencies`

Which validation runs, re-validation runs and actions used this rule, and
whether it is therefore safe to retire.

```json
{
  "rule_id": "rule-sigma-01",
  "dependent_count": 2,
  "safe_to_delete": false,
  "report": "Rule 'rule-sigma-01' has 2 dependent(s):\n  - 2 validation_run(s)",
  "dependencies": [
    {
      "rule_id": "rule-sigma-01",
      "dependent_type": "validation_run",
      "dependent_id": "run-001",
      "recorded_at": "2026-09-16T09:20:00+00:00",
      "metadata": {}
    }
  ]
}
```

#### `POST /api/v2/rules/{rule_id}/dependencies` → `201`

Called by the Validation Engine whenever it actually executes a rule version.

```json
{
  "dependent_type": "validation_run",
  "dependent_id": "run-001",
  "metadata": { "action_id": "act-501" }
}
```

`dependent_type` must be one of `validation_run`, `revalidation_run`, `action`;
anything else → `400`.

#### `GET /api/v2/rules/{rule_id}/impact`

Pre-flight check before deleting or editing a rule. Returns the full dependent
list plus `safe_to_delete` / `safe_to_edit`.

### 3.2 Connectors — `/api/v2/connectors`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/register` | Register a connector class from a module in the `app.connector.*` namespace. |
| `GET` | `/registered` | List registered connectors. |
| `GET` | `/{vendor}` | Metadata for one connector. |
| `GET` | `/health` | Health for all registered connectors. |
| `GET` | `/health/{connector_id}` | Health for one connector. |
| `POST` | `/health/{connector_id}/query` | Record a query result (latency, success) for health scoring. |
| `POST` | `/health/{connector_id}/connection` | Record a connection-status change. |
| `POST` | `/health/{connector_id}/register` | Register a connector's health record. |

Built-in connectors: **Splunk** (SPL), **Microsoft Sentinel** (KQL), **Elastic
Security** (EQL/KQL), **IBM QRadar** (AQL), **CrowdStrike LogScale** (LQL).

### 3.3 Health

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Service banner. |
| `GET` | `/health` | Liveness check. |

---

## 4. Data models

### `ParsedRule`

The normalized representation of an ingested detection rule. Key fields:
`rule_id`, `title`, `description`, `author`, `content_hash` (64-char SHA-256),
`version`, `rule_format`, `mitre_techniques`, `detection_logic`, `syntax_valid`,
`validation_errors`, `severity`, `tags`, `created_at`, `updated_at`,
`is_active`.

`detection_logic` is a **structured mapping for Sigma** and the **raw query
string for KQL** — hence its `Union[Dict[str, Any], str]` type.

Invariants enforced by validators:

* `mitre_techniques` must match `^T\d{4}(\.\d{3})?$`.
* `severity` ∈ `{low, medium, high, critical}`.
* `syntax_valid = true` is incompatible with a non-empty `validation_errors`.

### `SyntaxValidationReport`

Per-rule validation outcome: `rule_id`, `file_name`, `syntax_valid`,
`validation_errors`, `validation_warnings`, `validated_at`.

---

## 5. Rule lifecycle and versioning semantics

Rules are **content-addressed**: the SHA-256 of the raw file content is the
identity of a revision.

1. **First ingest** → version `1`, `is_latest = true`, status `active`.
2. **Identical content re-ingested** → no-op. Idempotent by design.
3. **Changed content** → new version (`version + 1`), previous revision is
   superseded (`is_latest = false`). The superseded hash is **never deleted**,
   so a verdict produced by it stays explainable.
4. **Deprecation** → status becomes `deprecated`; every revision stays
   addressable. Dependents are reported, not blocked.
5. **Restore** → status returns to `active`.

The `detection_rules` table enforces `UNIQUE(rule_id, version)` and
`UNIQUE(content_hash)` to make these transitions safe under concurrency.

---

## 6. Project layout

```
rule ingestion/
├── alembic/                    # Migration environment (alembic.ini at root)
│   └── versions/               # Revision scripts
├── app/
│   ├── api/                    # FastAPI routers (rules, connectors)
│   ├── connector/              # BaseConnector, registry, SIEM connectors,
│   │                           # retry, circuit breaker, credential manager
│   ├── models/                 # Pydantic models + Alembic revision for
│   │                           # detection_rules
│   └── services/               # parsers, validation, versioning,
│                               # dependency tracker, update detector
├── docs/                       # Connector development guide
└── tests/                      # Unit + integration + performance suites
```

---

## 7. Testing

```bash
pytest                                    # everything
pytest tests/test_rule_ingestion_integration.py   # W3 integration suite
pytest tests/test_alembic_migrations.py   # migration DDL (offline, no DB)
SKIP_PERFORMANCE_TESTS=1 pytest           # skip the 1000-rule throughput run
```

Notable suites:

| Suite | Covers |
|---|---|
| `test_rule_ingestion_integration.py` | End-to-end ingest of a fixture repo with 10 Sigma + 5 KQL rules |
| `test_rule_versioning.py` | Version history, supersession, deprecation, dependency tracker |
| `test_alembic_migrations.py` | Alembic discovers the revision and renders correct DDL |
| `test_ingestion_performance.py` | Throughput for a 1000+ rule repository; parse-cache behaviour |
| `test_connector_integrations.py` | Connectors driven over HTTP against an in-process mock SIEM |

CI runs `pytest` from this directory on Python 3.13 (see
`.github/workflows/ci.yml` at the repository root).
