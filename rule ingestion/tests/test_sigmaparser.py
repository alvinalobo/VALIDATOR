import yaml
from typing import Any, Dict, List, Optional

from app.models.rule_models import ParsedRule, RuleFormatEnum  # Pydantic model response schema


def _normalize_mitre_tag(tag: Any) -> Optional[str]:
    if isinstance(tag, str):
        normalized = tag.strip().lower()
        if normalized.startswith("attack.t"):
            _, _, technique = normalized.partition(".")
            return technique.upper() if technique else None
    elif isinstance(tag, dict):
        namespace = tag.get("namespace")
        name = tag.get("name")
        if (
            isinstance(namespace, str)
            and namespace.lower() == "attack"
            and isinstance(name, str)
            and name.lower().startswith("t")
        ):
            return name.upper()
    return None


def _extract_mitre_techniques(tags: Any) -> List[str]:
    if not tags:
        return []

    techniques: List[str] = []
    if isinstance(tags, str):
        tags = [tags]

    for tag in tags:
        tech_id = _normalize_mitre_tag(tag)
        if tech_id:
            techniques.append(tech_id)

    return techniques


def parse_sigma(raw_yaml: str, content_hash: str) -> ParsedRule:
    validation_errors: List[str] = []
    syntax_valid = True
    rule_id = "UNKNOWN"
    title = "UNKNOWN"
    description: Optional[str] = None
    author: Optional[str] = None
    mitre_techniques: List[str] = []
    detection_logic: Dict[str, Any] = {}
    tags: List[str] = []

    try:
        data = yaml.safe_load(raw_yaml)

        if data is None:
            raise ValueError("Rule file is empty")
        if not isinstance(data, dict):
            raise ValueError(
                f"Sigma rule root must be a mapping, got {type(data).__name__}"
            )

        rule_id = str(data.get("id")).strip() if data.get("id") else "UNKNOWN"
        title = str(data.get("title")).strip() if data.get("title") else "UNKNOWN"
        description = data.get("description")
        author = data.get("author")
        detection_logic = data.get("detection", {})
        raw_tags = data.get("tags", [])
        tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
        mitre_techniques = _extract_mitre_techniques(raw_tags)

        if not data.get("id"):
            validation_errors.append("Missing required field: id")
        if not data.get("title"):
            validation_errors.append("Missing required field: title")
        if not description:
            validation_errors.append("Missing required field: description")
        if not mitre_techniques:
            validation_errors.append("Missing required field: MITRE ATT&CK tags")
        if not data.get("detection"):
            validation_errors.append("Missing required field: detection logic")

    except yaml.YAMLError as exc:
        syntax_valid = False
        validation_errors.append(f"Invalid YAML syntax: {exc}")
        detection_logic = {}
    except Exception as exc:
        syntax_valid = False
        validation_errors.append(str(exc))
        detection_logic = {}

    if validation_errors:
        syntax_valid = False

    return ParsedRule(
        rule_id=rule_id,
        title=title,
        description=description,
        author=author,
        content_hash=content_hash,
        rule_format=RuleFormatEnum.SIGMA,
        mitre_techniques=mitre_techniques,
        detection_logic=detection_logic,
        syntax_valid=syntax_valid,
        validation_errors=validation_errors,
        tags=tags,
    )