import json
from pathlib import Path

from jsonschema import Draft202012Validator


SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "verdict schema"
    / "verdict_schema.json"
)


def load_verdict_schema():
    with SCHEMA_PATH.open("r", encoding="utf-8") as schema_file:
        return json.load(schema_file)


def test_verdict_schema_accepts_v2_event():
    schema = load_verdict_schema()

    verdict_event = {
        "action_id": "action-001",
        "verdict": "Detected",
        "confidence": 0.95,
        "causal_chain": [
            "evidence-matched",
            "rule-validated",
            "verdict-generated",
        ],
        "mttd_seconds": 12.5,
        "matched_evidence_ref": "evidence-001",
        "regulatory_control_refs": ["AC-2"],
        "content_hash": "a" * 64,
    }

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    errors = list(validator.iter_errors(verdict_event))

    assert errors == []


def test_verdict_schema_rejects_missing_v2_fields():
    schema = load_verdict_schema()
    validator = Draft202012Validator(schema)

    verdict_event = {
        "action_id": "action-001",
        "verdict": "Detected",
        "confidence": 0.95,
        "causal_chain": [],
        "mttd_seconds": 12.5,
        "matched_evidence_ref": "evidence-001",
    }

    errors = list(validator.iter_errors(verdict_event))

    assert errors
