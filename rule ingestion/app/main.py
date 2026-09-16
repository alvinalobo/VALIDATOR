"""
Rule Ingestion Service — application entrypoint.

Week 11 deliverable: publish real API documentation. FastAPI generates the
OpenAPI schema automatically from the route signatures, but the generated
documentation is only useful if the service-level metadata (description, tag
groups, per-endpoint summaries) is actually filled in — hence the explicit
configuration below.

Interactive documentation is served at:
    /docs      Swagger UI
    /redoc     ReDoc
    /openapi.json
"""

from fastapi import FastAPI

from app.api.connector_routes import router as connector_router
from app.api.rules import router as rule_router
from app.connector.plugin_loader import load_plugins

DESCRIPTION = """
The **Rule Ingestion Service** is the Module 1 component of The Validator. It
ingests detection rules (Sigma and KQL) from Git repositories, parses and
validates them, and keeps a content-addressed history of every rule revision so
that past verdicts remain reproducible after a rule changes.

### Responsibilities

* **Rule ingestion** — clone a Git repository, discover `.yml`/`.yaml`/`.kql`
  files, parse them (pySigma where the rule satisfies the Sigma specification,
  a lenient YAML path otherwise so incomplete rules can still be reported on),
  and record each revision by SHA-256 content hash.
* **Syntax validation** — verify required fields (title, detection logic,
  MITRE technique mapping) and produce a per-rule validation report.
* **Rule versioning and dependencies** — track the full revision history of
  every rule, and record which validation runs depend on which rule version so
  a rule can be retired without stranding a verdict's audit trail.
* **Connector framework** — a plugin registry of SIEM connectors (Splunk,
  Microsoft Sentinel, Elastic Security, IBM QRadar, CrowdStrike LogScale) with
  retry, circuit-breaking and health scoring, exposed for the Validation
  Engine (Pod Beta) to execute queries through.

### Consumers

* **Pod Beta (Validation Engine)** executes detection rules and records
  dependencies back through `/api/v2/rules/{rule_id}/dependencies`.
* **Pod Gamma / Pod Delta** consume the connector health and registration
  surfaces.
"""

TAGS_METADATA = [
    {
        "name": "rules",
        "description": (
            "Rule ingestion, search/filtering, version history and the rule "
            "dependency tracker."
        ),
    },
    {
        "name": "connectors",
        "description": (
            "SIEM connector registration, configuration validation and health "
            "monitoring."
        ),
    },
    {
        "name": "health",
        "description": "Service liveness and readiness endpoints.",
    },
]

app = FastAPI(
    title="Rule Ingestion Service",
    description=DESCRIPTION,
    version="1.0.0",
    openapi_tags=TAGS_METADATA,
    contact={
        "name": "CyArt Tech LLP — Pod Alpha",
    },
    license_info={
        "name": "Proprietary",
    },
)

# Register connectors declared as plugins before any route can reference them.
load_plugins()

app.include_router(connector_router)
app.include_router(rule_router)


@app.get("/", tags=["health"], summary="Service banner")
def home():
    """Basic liveness banner identifying the running service."""
    return {"message": "Rule Ingestion Service is running"}


@app.get("/health", tags=["health"], summary="Liveness check")
def health():
    """Returns healthy once the application has started and plugins loaded."""
    return {"status": "healthy"}
