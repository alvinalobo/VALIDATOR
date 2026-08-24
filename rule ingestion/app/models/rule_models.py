from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

class RuleFormatEnum(str, Enum):
    SIGMA = "sigma"
    KQL = "kql"
    YARA = "yara"


RuleFormat = RuleFormatEnum"


class RuleIngestRequest(BaseModel):
    """
    Request model for ingesting detection rules from a Git repository.
    
    Attributes:
        repo_url: Valid Git repository URL
        branch: Git branch, tag, or commit hash (default: main)
        rule_types: List of rule formats to ingest
        include_validation: Whether to validate rules during ingestion
        tags: Optional tags to apply to all ingested rules
    """
    repo_url: HttpUrl = Field(
        ..., 
        description="Git repository URL (must be valid HTTP/HTTPS URL)"
    )
    branch: str = Field(
        default="main",
        min_length=1,
        max_length=255,
        description="Git branch, tag, or commit hash"
    )
    rule_types: List[RuleFormatEnum] = Field(
        default=[RuleFormatEnum.SIGMA, RuleFormatEnum.KQL],
        min_items=1,
        description="Rule formats to ingest"
    )
    include_validation: bool = Field(
        default=True,
        description="Whether to validate rules during ingestion"
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description="Optional tags to apply to all ingested rules"
    )

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v):
        """Ensure repository URL is a Git repository"""
        url_str = str(v)
        if not url_str.endswith(".git") and not any(
            host in url_str for host in ["github.com", "gitlab.com", "bitbucket.org"]
        ):
            # Allow non-.git URLs from known Git hosting providers
            pass
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v):
        """Validate tags are non-empty strings"""
        if v is not None:
            for tag in v:
                if not tag.strip():
                    raise ValueError("Tags cannot be empty strings")
        return v


class ParsedRule(BaseModel):
    """
    Internal representation of a successfully parsed detection rule.
    
    Attributes:
        rule_id: Unique rule identifier
        title: Rule title/name
        description: Detailed description of what the rule detects
        author: Rule author or source
        content_hash: SHA-256 hash of rule content for change detection
        rule_format: Format of the rule (sigma, kql, yara)
        mitre_techniques: Mapped MITRE ATT&CK technique IDs
        detection_logic: Normalized detection logic structure
        syntax_valid: Whether rule passed syntax validation
        validation_errors: List of validation issues found
        severity: Rule severity level
        tags: Categorization tags
        created_at: When rule was created
        updated_at: When rule was last updated
    """
    rule_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Unique rule identifier (must be unique within system)"
    )
    title: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Rule title or name"
    )
    description: Optional[str] = Field(
        default=None,
        max_length=5000,
        description="Detailed description of detection logic"
    )
    author: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Rule author or source organization"
    )
    content_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 hash of rule content"
    )

    version: int = Field(
    default=1,
    ge=1,
    description="Current version of the rule"

    )
    rule_format: RuleFormatEnum = Field(
        ...,
        description="Rule format type"
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g., T1234, T1234.001)"
    )
    detection_logic: Dict[str, Any] = Field(
        default_factory=dict,
        description="Normalized detection logic (parsed rule content)"
    )
    syntax_valid: bool = Field(
        ...,
        description="Whether rule passed syntax validation"
    )
    validation_errors: List[str] = Field(
        default_factory=list,
        description="List of syntax validation errors (empty if valid)"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Rule severity (e.g., low, medium, high, critical)"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Categorization tags for rule discovery"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when rule was created"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp of last rule modification"
    )

    @field_validator("mitre_techniques")
    @classmethod
    def validate_mitre_ids(cls, v):
        """Validate MITRE ATT&CK ID format"""
        import re
        mitre_pattern = re.compile(r"^T\d{4}(?:\.\d{3})?$")
        for technique in v:
            if not mitre_pattern.match(technique):
                raise ValueError(
                    f"Invalid MITRE ATT&CK ID format: {technique}. "
                    "Expected format: T1234 or T1234.001"
                )
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        """Validate severity is from allowed values"""
        if v is not None:
            allowed = {"low", "medium", "high", "critical"}
            if v.lower() not in allowed:
                raise ValueError(
                    f"Severity must be one of: {allowed}. Got: {v}"
                )
        return v

    @model_validator(mode="after")
    def validate_syntax_consistency(self):
        """Ensure syntax_valid and validation_errors are consistent"""
        if self.syntax_valid and self.validation_errors:
            raise ValueError(
                "Rule cannot be valid (syntax_valid=True) "
                "if validation_errors are present"
            )
        return self


class SyntaxValidationReport(BaseModel):
    """
    Report generated after validating a rule.
    
    Attributes:
        rule_id: Identifier of validated rule
        file_name: Source file path
        syntax_valid: Whether validation passed
        validation_errors: List of errors found
        validation_warnings: Non-critical warnings
        validated_at: When validation occurred
    """
    rule_id: str = Field(
        ...,
        description="Rule identifier"
    )
    file_name: str = Field(
        ...,
        description="Source rule file path or name"
    )
    syntax_valid: bool = Field(
        ...,
        description="Whether rule passed syntax validation"
    )
    validation_errors: List[str] = Field(
        default_factory=list,
        description="Critical validation errors"
    )
    validation_warnings: List[str] = Field(
        default_factory=list,
        description="Non-critical validation warnings"
    )
    validated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When validation was performed"
    )

    @model_validator(mode="after")
    def validate_error_consistency(self):
        """Ensure error list is empty when valid"""
        if self.syntax_valid and self.validation_errors:
            raise ValueError(
                "Cannot be valid (syntax_valid=True) with errors present"
            )
        return self


class RuleIngestResponse(BaseModel):
    """
    Response model for rule ingestion operation.
    
    Attributes:
        total_processed: Total rules processed
        successfully_ingested: Count of successfully ingested rules
        failed_count: Count of failed ingestions
        validation_passed: Count of rules passing validation
        validation_failed: Count of rules failing validation
        ingested_rules: List of successfully ingested rule IDs
        errors: List of ingestion errors
    """
    total_processed: int = Field(..., ge=0, description="Total rules processed")
    successfully_ingested: int = Field(
        ..., ge=0, description="Successfully ingested rules count"
    )
    failed_count: int = Field(..., ge=0, description="Failed rules count")
    validation_passed: int = Field(
        ..., ge=0, description="Rules passing validation"
    )
    validation_failed: int = Field(
        ..., ge=0, description="Rules failing validation"
    )
    ingested_rules: List[str] = Field(
        default_factory=list,
        description="IDs of successfully ingested rules"
    )
    errors: List[str] = Field(
        default_factory=list,
        description="Detailed error messages"
    )
    completed_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When ingestion completed"
    )


class BulkValidationResponse(BaseModel):
    """
    Response model for bulk rule validation.
    
    Attributes:
        total_validated: Total rules validated
        passed: Count of rules passing validation
        failed: Count of rules failing validation
        results: Detailed validation report for each rule
    """
    total_validated: int = Field(..., ge=0, description="Total rules validated")
    passed: int = Field(..., ge=0, description="Rules passing validation")
    failed: int = Field(..., ge=0, description="Rules failing validation")
    results: List[SyntaxValidationReport] = Field(
        default_factory=list,
        description="Detailed validation results"
    )
    completed_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When validation completed"
    )
