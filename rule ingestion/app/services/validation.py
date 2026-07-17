

from typing import Any, Dict, List, Tuple

_BALANCED_PAIRS = {"(": ")", "[": "]", "{": "}"}


def _check_balanced(text: str) -> bool:
    stack: List[str] = []
    for char in text:
        if char in _BALANCED_PAIRS:
            stack.append(char)
        elif char in _BALANCED_PAIRS.values():
            if not stack or _BALANCED_PAIRS[stack.pop()] != char:
                return False
    return not stack


def validate_sigma(parsed: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Structural checks beyond "did it parse":
    - detection must be a mapping
    - detection must contain a 'condition' key
    - detection must contain at least one selection block referenced logically
    """
    errors: List[str] = []
    detection = parsed.get("detection_logic")

    if not isinstance(detection, dict):
        errors.append("'detection' must be a mapping of selections + condition")
        return False, errors

    if "condition" not in detection:
        errors.append("'detection' is missing a 'condition' field")

    selections = [k for k in detection.keys() if k != "condition"]
    if not selections:
        errors.append("'detection' has no selection blocks defined")

    return (len(errors) == 0), errors


def validate_kql(parsed: Dict[str, Any]) -> Tuple[bool, List[str]]:
 
    errors: List[str] = []
    query = parsed.get("detection_logic", "") or ""
    lines = [ln.strip() for ln in query.splitlines() if ln.strip()]

    if not lines:
        errors.append("Query body is empty")
        return False, errors

    if lines[0].startswith("|"):
        errors.append("Query must start with a source table, not a pipe operator")

    if "|" not in query:
        errors.append("Query has no pipe ('|') operators — likely incomplete")

    if not _check_balanced(query):
        errors.append("Unbalanced parentheses/brackets/braces in query")

    return (len(errors) == 0), errors
