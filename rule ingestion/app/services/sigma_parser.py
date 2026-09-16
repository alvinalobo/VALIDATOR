"""
sigma_parser.py

Single responsibility: turn raw Sigma YAML text into a structured dict
that rule_pipeline.py can lift into a ParsedRule. Does NOT validate
correctness beyond what's needed to extract fields — that's validation.py's job.

Parsing strategy (Week 3 deliverable)
-------------------------------------
The pySigma library is the primary parser. It enforces the Sigma
specification properly (logsource required, well-formed detection block,
valid modifier chain), which is what you want for the bulk of a real rule
repository.

pySigma is deliberately *strict*, though, and a detection-engineering
repository will always contain some rules that do not yet satisfy the full
spec. Those rules must still be ingested so that the syntax-validation step
can report *what* is wrong with them, rather than the whole ingest run
failing on one malformed file. So when pySigma rejects a rule for a
structural reason we fall back to a lenient YAML parse and let validation.py
produce the report.

The returned dict carries `parsed_by` ("pysigma" or "yaml") so callers and
tests can tell which path handled a given rule.
"""

from typing import Any, Dict, List
import re

import yaml

try:  # pySigma is the preferred parser; see module docstring.
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError

    _PYSIGMA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without pySigma installed
    SigmaCollection = None  # type: ignore[assignment]
    SigmaError = None  # type: ignore[assignment]
    _PYSIGMA_AVAILABLE = False


class SigmaParseError(Exception):
    """Raised when a Sigma rule cannot be parsed at all (bad YAML, wrong shape)."""


# MITRE technique ids as they appear in Sigma tag names: t1059 or t1059.001.
_MITRE_TECHNIQUE_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$")


def _extract_mitre_techniques(tags: List[Any]) -> List[str]:
    """
    Sigma convention: MITRE ATT&CK techniques appear as tags like
    'attack.t1059.001' or 'attack.t1105'. Pull those out and normalize.

    Accepts either raw tag strings (lenient YAML path) or pySigma
    `SigmaRuleTag` objects, whose `name` attribute holds the technique id
    without the 'attack.' namespace prefix.
    """
    techniques: List[str] = []
    for tag in tags or []:
        if isinstance(tag, str):
            candidate = tag.strip().lower()
            # 'attack.t1059.001' -> 't1059.001'
            if candidate.startswith("attack."):
                candidate = candidate.split(".", 1)[1]
        else:
            name = getattr(tag, "name", None)
            if not isinstance(name, str):
                continue
            candidate = name.strip().lower()

        # Only real technique ids count — this drops 'attack.execution',
        # 'attack.persistence' and similar tactic tags.
        if _MITRE_TECHNIQUE_RE.match(candidate):
            techniques.append(candidate.upper())
    return techniques


def _parse_with_yaml(content: str) -> Dict[str, Any]:
    """
    Lenient fallback parser: plain YAML plus the structural fields the
    pipeline needs. Used when pySigma is unavailable or rejects a rule that
    is still parseable well enough to be validated and reported on.
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise SigmaParseError(f"Invalid YAML syntax: {exc}") from exc

    if data is None:
        raise SigmaParseError("Rule file is empty")

    if not isinstance(data, dict):
        raise SigmaParseError(
            f"Sigma rule root must be a mapping, got {type(data).__name__}"
        )

    title = data.get("title")
    detection = data.get("detection")

    if not title:
        raise SigmaParseError("Missing required field: 'title'")
    if detection is None:
        raise SigmaParseError("Missing required field: 'detection'")

    status = str(data.get("status", "")).lower()
    is_active = status not in ("deprecated", "unsupported")

    return {
        "rule_id": data.get("id"),
        "title": title,
        "description": data.get("description"),
        "author": data.get("author"),
        "detection_logic": detection,
        "mitre_techniques": _extract_mitre_techniques(data.get("tags", [])),
        "raw": data,
        "is_active": is_active,
        "parsed_by": "yaml",
    }


def _parse_with_sigma_library(content: str) -> Dict[str, Any]:
    """
    Parse using pySigma, which validates the rule against the Sigma
    specification and normalizes its metadata.

    Detection logic is taken from the rule's own `detection` mapping so the
    stored shape stays identical to the fallback path (the rest of the
    pipeline and the validation step both depend on that shape).
    """
    collection = SigmaCollection.from_yaml(content)

    if not collection.rules:
        raise SigmaParseError("Sigma rule file contained no rules")

    if len(collection.rules) > 1:
        raise SigmaParseError(
            f"Sigma rule file contained {len(collection.rules)} rules; "
            "the ingestion pipeline expects one rule per file"
        )

    rule = collection.rules[0]

    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise SigmaParseError(
            f"Sigma rule root must be a mapping, got {type(data).__name__}"
        )

    if not rule.title:
        raise SigmaParseError("Missing required field: 'title'")

    detection = data.get("detection")
    if detection is None:
        raise SigmaParseError("Missing required field: 'detection'")

    status = rule.status.name.lower() if rule.status else ""

    return {
        "rule_id": str(rule.id) if rule.id else data.get("id"),
        "title": rule.title,
        "description": rule.description,
        "author": rule.author,
        "detection_logic": detection,
        # pySigma's tags carry the technique in `.name`, without the namespace.
        "mitre_techniques": _extract_mitre_techniques(rule.tags),
        "raw": data,
        "is_active": status not in ("deprecated", "unsupported"),
        "parsed_by": "pysigma",
    }


# Failures that mean "pySigma would not accept this rule" rather than a
# programming error: spec violations, malformed YAML, bad attribute access.
_PYSIGMA_REJECTION_ERRORS = (
    (SigmaError,) if _PYSIGMA_AVAILABLE else ()
) + (yaml.YAMLError, ValueError, TypeError, KeyError, AttributeError)


def parse_sigma_rule(content: str) -> Dict[str, Any]:
    """
    Parse a single Sigma rule file's contents.

    Returns a dict with the fields ParsedRule needs. Raises SigmaParseError
    on malformed YAML or a missing structural field required to even
    attempt validation later (title, detection).
    """
    if _PYSIGMA_AVAILABLE:
        try:
            return _parse_with_sigma_library(content)
        except _PYSIGMA_REJECTION_ERRORS:
            # pySigma enforces the full specification. Rules that fall short
            # are still ingested via the lenient parser so validation.py can
            # report precisely what is missing instead of the rule silently
            # disappearing from the ingest run.
            pass

    return _parse_with_yaml(content)
