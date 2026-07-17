
from typing import Any, Dict, List, Tuple

# Which fields are required. Adjust here if the requirement changes —
# nothing else in the pipeline needs to change.
REQUIRED_FIELDS = ("title", "description", "detection_logic", "mitre_techniques")


def _is_blank(value: Any) -> bool:
    """True if the field is missing, None, an empty string, or an empty
    collection (list/dict) — all of which count as 'not provided'."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) == 0
    return False


def check_mandatory_fields(parsed: Dict[str, Any]) -> Tuple[bool, List[str]]:
   
    missing: List[str] = []

    for field in REQUIRED_FIELDS:
        if field not in parsed or _is_blank(parsed.get(field)):
            missing.append(field)

    return (len(missing) == 0), missing


def check_mandatory_fields_report(parsed: Dict[str, Any]) -> str:
   
    is_complete, missing = check_mandatory_fields(parsed)
    if is_complete:
        return "All mandatory fields present"
    return f"Missing mandatory field(s): {', '.join(missing)}"