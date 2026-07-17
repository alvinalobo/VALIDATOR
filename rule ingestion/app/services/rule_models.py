"""
Shared Pydantic models for the Rule Ingestion Service (Pod Alpha).
"""

from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


class RuleFormat(str, Enum):
    SIGMA = "sigma"
    KQL = "kql"


class RuleIngestRequest(BaseModel):
    repo_url: str = Field(..., description="Git URL of the rule repository")
    branch: str = Field(default="main", description="Branch to clone")
    rule_types: List[RuleFormat] = Field(
        default_factory=lambda: [RuleFormat.SIGMA, RuleFormat.KQL],
        description="Which rule formats to discover and parse",
    )


class ParsedRule(BaseModel):
    rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    author: Optional[str] = None
    content_hash: str
    rule_format: RuleFormat
    detection_logic: Any = None
    mitre_techniques: List[str] = Field(default_factory=list)
    syntax_valid: bool = True
    validation_errors: List[str] = Field(default_factory=list)

    # Bookkeeping fields — useful for debugging/audit, safe to ignore downstream.
    file_path: Optional[str] = None


class SyntaxValidationReport(BaseModel):
    total_rules: int = 0
    valid_rules: int = 0
    invalid_rules: int = 0
    failed_rule_ids: List[str] = Field(default_factory=list)
    errors: Dict[str, List[str]] = Field(default_factory=dict)

    def record(self, rule: ParsedRule) -> None:
        """Fold a single ParsedRule's outcome into the running report."""
        self.total_rules += 1
        if rule.syntax_valid:
            self.valid_rules += 1
        else:
            self.invalid_rules += 1
            identifier = rule.rule_id or rule.file_path or rule.title
            self.failed_rule_ids.append(identifier)
            self.errors[identifier] = rule.validation_errors
