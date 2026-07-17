"""
sigma_parser.py

Single responsibility: turn raw Sigma YAML text into a structured dict
that rule_pipeline.py can lift into a ParsedRule. Does NOT validate
correctness beyond what's needed to extract fields — that's validation.py's job.
"""

from typing import Any, Dict, List

import yaml


class SigmaParseError(Exception):
    """Raised when a Sigma rule cannot be parsed at all (bad YAML, wrong shape)."""


def _extract_mitre_techniques(tags: List[Any]) -> List[str]:
    """
    Sigma convention: MITRE ATT&CK techniques appear as tags like
    'attack.t1059.001' or 'attack.t1105'. Pull those out and normalize.
    """
    techniques = []
    for tag in tags or []:
        if isinstance(tag, str) and tag.lower().startswith("attack.t"):
            # 'attack.t1059.001' -> 'T1059.001'
            technique = tag.split(".", 1)[1]
            techniques.append(technique.upper())
    return techniques


def parse_sigma_rule(content: str) -> Dict[str, Any]:
    """
    Parse a single Sigma rule file's contents.

    Returns a dict with the fields ParsedRule needs. Raises SigmaParseError
    on malformed YAML or a missing structural field required to even
    attempt validation later (title, detection).
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

    return {
        "rule_id": data.get("id"),
        "title": title,
        "description": data.get("description"),
        "author": data.get("author"),
        "detection_logic": detection,
        "mitre_techniques": _extract_mitre_techniques(data.get("tags", [])),
        "raw": data,
    }
