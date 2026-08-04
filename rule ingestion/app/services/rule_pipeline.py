"""
rule_pipeline.py

Orchestrates the other services. Contains NO parsing/validation logic of
its own — it just wires things together in order:

    discover files -> read -> hash -> parse (sigma/kql) -> validate -> ParsedRule

Import paths below assume the standard `app.services.*` / `app.models.*`
package layout. Adjust if your project uses a different package root.
"""

import logging
from pathlib import Path
from typing import List, Tuple

from app.models.rule_models import ParsedRule, RuleFormat, SyntaxValidationReport
from app.services.hashing import compute_sha256
from app.services.sigma_parser import parse_sigma_rule, SigmaParseError
from app.services.kql_parser import parse_kql_rule, KqlParseError
from app.services.validation import validate_sigma, validate_kql

logger = logging.getLogger(__name__)

_EXTENSION_FORMAT = {
    ".yml": RuleFormat.SIGMA,
    ".yaml": RuleFormat.SIGMA,
    ".kql": RuleFormat.KQL,
}


def _format_for_path(path: Path) -> RuleFormat:
    fmt = _EXTENSION_FORMAT.get(path.suffix.lower())
    if fmt is None:
        raise ValueError(f"Unsupported rule file extension: {path.suffix}")
    return fmt


def _build_invalid_rule(
    file_path: Path, content_hash: str, rule_format: RuleFormat, error: str
) -> ParsedRule:
    """A rule that failed to parse at all still gets a ParsedRule record,
    just marked invalid, so it shows up in the SyntaxValidationReport
    instead of silently disappearing."""
    return ParsedRule(
        rule_id=None,
        title=file_path.stem,
        description=None,
        author=None,
        content_hash=content_hash,
        version=1,
        rule_format=rule_format,
        detection_logic=None,
        mitre_techniques=[],
        syntax_valid=False,
        validation_errors=[error],
        file_path=str(file_path),
    )


def process_rule_file(file_path: Path) -> ParsedRule:
    """
    Run a single rule file through the full pipeline:
    read -> hash -> parse -> validate -> ParsedRule.

    Never raises — any failure (bad encoding, parse error, unsupported
    extension) is captured as an invalid ParsedRule so one bad rule
    file can't take down a whole ingestion run.
    """
    try:
        rule_format = _format_for_path(file_path)
    except ValueError as exc:
        # We can't even hash/read meaningfully without knowing the format,
        # but we still try, so the error surfaces per-file rather than
        # aborting the whole batch.
        content = file_path.read_text(encoding="utf-8", errors="replace")
        content_hash = compute_sha256(content)
        return _build_invalid_rule(file_path, content_hash, RuleFormat.SIGMA, str(exc))

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        return _build_invalid_rule(file_path, "", rule_format, f"Could not read file: {exc}")

    content_hash = compute_sha256(content)

    try:
        if rule_format == RuleFormat.SIGMA:
            parsed = parse_sigma_rule(content)
        else:
            parsed = parse_kql_rule(content)
    except (SigmaParseError, KqlParseError) as exc:
        logger.warning("Failed to parse %s: %s", file_path, exc)
        return _build_invalid_rule(file_path, content_hash, rule_format, str(exc))

    if rule_format == RuleFormat.SIGMA:
        is_valid, errors = validate_sigma(parsed)
    else:
        is_valid, errors = validate_kql(parsed)

    return ParsedRule(
        rule_id=parsed.get("rule_id"),
        title=parsed["title"],
        description=parsed.get("description"),
        author=parsed.get("author"),
        content_hash=content_hash,
        version=1,
        rule_format=rule_format,
        detection_logic=parsed.get("detection_logic"),
        mitre_techniques=parsed.get("mitre_techniques", []),
        syntax_valid=is_valid,
        validation_errors=errors,
        file_path=str(file_path),
    )


def run_pipeline(rule_files: List[Path]) -> Tuple[List[ParsedRule], SyntaxValidationReport]:
    """
    Entry point called by the /ingest endpoint (or file_discovery caller).

    Takes the list of file paths already discovered by file_discovery.py,
    runs each through process_rule_file, and returns both the parsed
    rules and a rolled-up SyntaxValidationReport.
    """
    report = SyntaxValidationReport()
    parsed_rules: List[ParsedRule] = []

    for file_path in rule_files:
        rule = process_rule_file(file_path)
        parsed_rules.append(rule)
        report.record(rule)

    return parsed_rules, report
