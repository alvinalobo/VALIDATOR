"""
kql_parser.py

Single responsibility: turn raw KQL text into a structured dict.

KQL has no native metadata block the way Sigma's YAML does, so this parser
expects metadata as a leading comment header, one `key: value` pair per
line, e.g.:

    // title: Suspicious PowerShell Download
    // description: Detects encoded PowerShell downloading a remote payload
    // author: security-team
    // mitre: T1059.001, T1105

    DeviceProcessEvents
    | where FileName == "powershell.exe"
    | where ProcessCommandLine has "-enc"

Everything after the comment header is treated as the detection query.
If your team already has a different metadata convention (e.g. a
sidecar .meta.json per rule, or a YAML frontmatter block), swap the
`_extract_header` function below — the rest of the pipeline only
depends on the returned dict shape.
"""

import re
from typing import Any, Dict, List, Tuple

COMMENT_PREFIX = "//"


class KqlParseError(Exception):
    """Raised when a KQL rule cannot be parsed (missing title, empty query, etc.)."""


def _extract_header(content: str) -> Tuple[Dict[str, str], str]:
    """
    Split leading `// key: value` comment lines from the rest of the file.
    Returns (metadata_dict, remaining_query_text).
    """
    lines = content.splitlines()
    metadata: Dict[str, str] = {}
    idx = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "":
            idx = i + 1
            continue
        if not stripped.startswith(COMMENT_PREFIX):
            idx = i
            break
        body = stripped[len(COMMENT_PREFIX):].strip()
        if ":" in body:
            key, _, value = body.partition(":")
            metadata[key.strip().lower()] = value.strip()
        idx = i + 1
    else:
        # File was entirely comments — no query body.
        idx = len(lines)

    query = "\n".join(lines[idx:]).strip()
    return metadata, query


def _extract_mitre_techniques(raw: str) -> List[str]:
    if not raw:
        return []
    return [t.strip().upper() for t in re.split(r"[,\s]+", raw) if t.strip()]


def parse_kql_rule(content: str) -> Dict[str, Any]:
    """
    Parse a single KQL rule file's contents.

    Raises KqlParseError if there's no title metadata or the query body
    is empty — those are the two things every downstream ParsedRule needs.
    """
    metadata, query = _extract_header(content)

    title = metadata.get("title")
    if not title:
        raise KqlParseError("Missing required metadata field: 'title'")
    if not query:
        raise KqlParseError("Rule has no detection query body")

    return {
        "rule_id": metadata.get("id"),
        "title": title,
        "description": metadata.get("description"),
        "author": metadata.get("author"),
        "detection_logic": query,
        "mitre_techniques": _extract_mitre_techniques(metadata.get("mitre", "")),
        "raw": metadata,
    }
