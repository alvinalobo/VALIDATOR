import math
from math import ceil
from fastapi import APIRouter, HTTPException, Query, Response, status
from typing import List, Dict, Optional, Union
import os
import hashlib
import shutil
import git

from pydantic import BaseModel
from app.models.rule_models import RuleIngestRequest, ParsedRule, RuleFormatEnum, PaginatedRuleResponse
from app.models.detection_rule import DetectionRule
from app.services.database import SessionLocal, create_tables
from app.services.sigma_parser import parse_sigma_rule
from app.services.kql_parser import parse_kql_rule
from app.services.rule_dependency_tracker import RuleDependencyTracker, RuleHasDependentsError
from app.services.rule_versioning import rule_versioning_service, RuleVersioningError

router = APIRouter(prefix="/api/v2/rules", tags=["rules"])

# In-memory database of parsed rules
INGESTED_RULES: Dict[str, ParsedRule] = {}

# Process-wide dependency tracker used by the rule APIs.
dependency_tracker = RuleDependencyTracker()

class RuleSearchResponse(BaseModel):
    items: List[ParsedRule]
    total: int
    page: int
    page_size: int
    total_pages: int

def clone_repo(repo_url: str, branch: str = 'main') -> str:
    # If repo_url is a local path, use it directly
    if os.path.exists(repo_url) and os.path.isdir(repo_url):
        return os.path.abspath(repo_url)
        
    # Generate unique directory name
    h = hashlib.sha256(repo_url.encode('utf-8')).hexdigest()[:12]
    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".cloned_repos"))
    os.makedirs(workspace_dir, exist_ok=True)
    repo_path = os.path.join(workspace_dir, f"{h}_{branch}")
    
    if os.path.exists(repo_path):
        try:
            repo = git.Repo(repo_path)
            repo.remotes.origin.fetch()
            repo.git.checkout(branch)
            repo.git.reset('--hard', f'origin/{branch}')
            return repo_path
        except Exception:
            shutil.rmtree(repo_path, ignore_errors=True)
            
    git.Repo.clone_from(repo_url, repo_path, branch=branch)
    return repo_path

def discover_rule_files(repo_path: str, rule_types: List[str]) -> List[str]:
    discovered = []
    for root, dirs, files in os.walk(repo_path):
        # Prevent traversing .git directories
        if ".git" in root.split(os.sep):
            continue
        for file in files:
            file_lower = file.lower()
            if 'sigma' in rule_types:
                if file_lower.endswith('.yml') or file_lower.endswith('.yaml'):
                    discovered.append(os.path.join(root, file))
            if 'kql' in rule_types:
                if file_lower.endswith('.kql'):
                    discovered.append(os.path.join(root, file))
    return sorted(discovered)

@router.post("/ingest", response_model=List[ParsedRule])
async def ingest_rules(req: RuleIngestRequest):
    try:
        repo_path = clone_repo(req.repo_url, req.branch)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to clone repository: {str(e)}")
        
    rule_files = discover_rule_files(repo_path, req.rule_types)
    rules = []
    
    for f in rule_files:
        try:
            with open(f, 'r', encoding='utf-8') as file_obj:
                raw = file_obj.read()
        except Exception:
            # Skip files we cannot read
            continue
            
        h = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        
        parsed_dict = None
        rule_format = None
        error_msg = None
        try:
            if f.endswith('.yml') or f.endswith('.yaml'):
                parsed_dict = parse_sigma_rule(raw)
                rule_format = RuleFormatEnum.SIGMA
            elif f.endswith('.kql'):
                parsed_dict = parse_kql_rule(raw)
                rule_format = RuleFormatEnum.KQL
        except Exception as e:
            error_msg = str(e)
            rule_format = RuleFormatEnum.SIGMA if (f.endswith('.yml') or f.endswith('.yaml')) else RuleFormatEnum.KQL
            
        if parsed_dict:
            raw_data = parsed_dict.get("raw", {})
            tags = [str(t) for t in raw_data.get("tags", [])] if isinstance(raw_data.get("tags"), list) else []
            severity = raw_data.get("severity") or raw_data.get("level")
            
            parsed = ParsedRule(
                rule_id=h,
                title=parsed_dict["title"],
                description=parsed_dict.get("description"),
                author=parsed_dict.get("author"),
                content_hash=h,
                rule_format=rule_format,
                mitre_techniques=parsed_dict.get("mitre_techniques") or [],
                detection_logic=parsed_dict.get("detection_logic"),
                syntax_valid=True,
                validation_errors=[],
                severity=severity,
                tags=tags,
                is_active=parsed_dict.get("is_active", True)
            )
            rules.append(parsed)
            # Keep the compatibility cache for existing callers/tests.
            INGESTED_RULES[parsed.rule_id] = parsed

            # Persist the latest rule in the shared detection_rules store.
            db = SessionLocal()
            try:
                existing = (
                    db.query(DetectionRule)
                    .filter(DetectionRule.content_hash == parsed.content_hash)
                    .first()
                )

                if existing is None:
                    db_rule = DetectionRule(
                        id=hashlib.md5(parsed.content_hash.encode()).hexdigest(),
                        rule_id=parsed.rule_id,
                        version=str(parsed.version),
                        title=parsed.title,
                        description=parsed.description,
                        author=parsed.author,
                        status="active" if parsed.is_active else "deprecated",
                        rule_format=parsed.rule_format.value,
                        severity=parsed.severity,
                        content_hash=parsed.content_hash,
                        syntax_valid=parsed.syntax_valid,
                        validation_errors=parsed.validation_errors,
                        mitre_techniques=parsed.mitre_techniques,
                        detection_logic=parsed.detection_logic,
                        tags=parsed.tags,
                        created_at=parsed.created_at,
                        updated_at=parsed.updated_at,
                    )
                    db.add(db_rule)
                    db.commit()
            finally:
                db.close()
        elif error_msg:
            parsed = ParsedRule(
                rule_id="UNKNOWN",
                title="UNKNOWN",
                content_hash=h,
                rule_format=rule_format,
                syntax_valid=False,
                validation_errors=[error_msg],
                is_active=True
            )
            rules.append(parsed)
            
    return rules

# ============================================================
# RULE SEARCH / FILTER / PAGINATION API (Defined before /{rule_id})
# ============================================================

@router.get("/search", response_model=Union[RuleSearchResponse, PaginatedRuleResponse, List[ParsedRule]])
async def search_rules(
    response: Response = None,
    q: str = Query(default="", description="Search term (matches title, description, tags)"),
    status: str = Query(default=None, description="Filter by status: active, deprecated"),
    severity: str = Query(default=None, description="Filter by severity: low, medium, high, critical"),
    mitre_technique: str = Query(default=None, description="Filter by MITRE technique ID (e.g. T1059)"),
    rule_format: str = Query(default=None, description="Filter by format: sigma, kql, yara"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
    sort_by: str = Query(default="created_at", description="Sort field: created_at, updated_at, title"),
    sort_order: str = Query(default="desc", description="Sort direction: asc, desc"),
    paginated: bool = Query(default=False, description="Whether to return a structured pagination envelope object"),
):
    """
    Search and filter rules with pagination and sorting.
    """
    results = list(INGESTED_RULES.values())

    # --- Filter by search term ---
    if q:
        q_lower = q.lower()
        results = [
            r for r in results
            if q_lower in (r.title or "").lower()
            or q_lower in (r.description or "").lower()
            or any(q_lower in tag.lower() for tag in r.tags)
        ]

    # --- Filter by status ---
    if status:
        status_value = status.lower()
        if status_value == "active":
            results = [r for r in results if r.is_active]
        elif status_value == "deprecated":
            results = [r for r in results if not r.is_active]
        else:
            raise HTTPException(
                status_code=400,
                detail="status must be one of: active, deprecated",
            )

    # --- Filter by severity ---
    if severity:
        results = [
            r for r in results
            if r.severity and r.severity.lower() == severity.lower()
        ]

    # --- Filter by MITRE technique ---
    if mitre_technique:
        tech = mitre_technique.upper()
        results = [
            r for r in results
            if tech in r.mitre_techniques
        ]

    # --- Filter by rule format ---
    if rule_format:
        format_value = rule_format.lower()
        allowed_formats = {"sigma", "kql", "yara"}
        if format_value not in allowed_formats:
            raise HTTPException(
                status_code=400,
                detail="rule_format must be one of: sigma, kql, yara",
            )
        results = [
            r for r in results
            if r.rule_format and r.rule_format.value == format_value
        ]

    # --- Sorting ---
    sort_fields = {
        "created_at": lambda r: r.created_at,
        "updated_at": lambda r: r.updated_at,
        "title": lambda r: (r.title or "").lower(),
    }
    sort_by_value = sort_by.lower()
    if sort_by_value not in sort_fields:
        raise HTTPException(
            status_code=400,
            detail="sort_by must be one of: created_at, updated_at, title",
        )
    sort_order_value = sort_order.lower()
    if sort_order_value not in {"asc", "desc"}:
        raise HTTPException(
            status_code=400,
            detail="sort_order must be one of: asc, desc",
        )
    sort_fn = sort_fields[sort_by_value]
    reverse = sort_order_value == "desc"
    results.sort(key=sort_fn, reverse=reverse)

    # --- Pagination ---
    total = len(results)
    total_pages = ceil(total / page_size) if total else 0
    start = (page - 1) * page_size
    end = start + page_size
    paginated_items = results[start:end]

    has_next = page < total_pages
    has_prev = page > 1 and total_pages > 0

    if response:
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Page"] = str(page)
        response.headers["X-Page-Size"] = str(page_size)
        response.headers["X-Total-Pages"] = str(total_pages)
        response.headers["X-Has-Next"] = "true" if has_next else "false"
        response.headers["X-Has-Prev"] = "true" if has_prev else "false"

    if paginated:
        return PaginatedRuleResponse(
            items=paginated_items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=has_next,
            has_prev=has_prev
        )

    return paginated_items

@router.get("/{rule_id}", response_model=ParsedRule)
async def get_rule(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

@router.post("/{rule_id}/deprecate")
async def deprecate_rule(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    rule = INGESTED_RULES[rule_id]
    rule.is_active = False

    try:
        rule_versioning_service.get_version_number(rule_id, 1)
        rule_versioning_service.deprecate(rule_id)
    except RuleVersioningError:
        rule_versioning_service.record_version(
            rule_id=rule_id,
            content_hash=rule.content_hash,
            title=rule.title,
            rule_format=rule.rule_format.value if hasattr(rule.rule_format, "value") else str(rule.rule_format),
        )
        rule_versioning_service.deprecate(rule_id)

    dependencies = dependency_tracker.get_dependents(rule.content_hash)

    return {
        "message": f"Rule '{rule_id}' was successfully deprecated.",
        "rule_id": rule_id,
        "is_active": False,
        "dependent_count": len(dependencies),
    }


@router.get("/{rule_id}/dependencies")
async def get_rule_dependencies(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    rule = INGESTED_RULES[rule_id]
    dependencies = dependency_tracker.get_dependents(rule.content_hash)

    return {
        "rule_id": rule_id,
        "dependent_count": len(dependencies),
        "safe_to_delete": len(dependencies) == 0,
        "dependencies": [
            {
                "dependent_type": dep.dependent_type,
                "dependent_id": dep.dependent_id,
                "recorded_at": dep.recorded_at,
                "metadata": dep.metadata,
            }
            for dep in dependencies
        ],
    }


@router.post("/{rule_id}/dependencies")
async def record_rule_dependency(rule_id: str, payload: Dict[str, object], response: Response):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    dependent_type = payload.get("dependent_type")
    dependent_id = payload.get("dependent_id")
    metadata = payload.get("metadata") or {}

    allowed_types = {"validation_run", "action", "revalidation_run"}

    if dependent_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid dependent_type. Expected one of: {sorted(allowed_types)}",
        )

    if not dependent_id:
        raise HTTPException(status_code=400, detail="dependent_id is required")

    rule = INGESTED_RULES[rule_id]
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=400, detail="metadata must be an object")

    dependency_tracker.record_usage(
        rule.content_hash,
        dependent_type,
        dependent_id,
        metadata=metadata,
    )
    response.status_code = status.HTTP_201_CREATED

    return {
        "rule_id": rule_id,
        "dependent_type": dependent_type,
        "dependent_id": dependent_id,
        "message": "Dependency recorded successfully.",
    }


@router.get("/{rule_id}/impact")
async def get_rule_impact(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    rule = INGESTED_RULES[rule_id]
    dependencies = dependency_tracker.get_dependents(rule.content_hash)

    return {
        "rule_id": rule_id,
        "dependent_count": len(dependencies),
        "safe_to_delete": len(dependencies) == 0,
        "safe_to_edit": len(dependencies) == 0,
        "dependencies": [
            {
                "dependent_type": dep.dependent_type,
                "dependent_id": dep.dependent_id,
                "recorded_at": dep.recorded_at,
                "metadata": dep.metadata,
            }
            for dep in dependencies
        ],
    }


@router.post("/{rule_id}/restore")
async def restore_rule(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    rule = INGESTED_RULES[rule_id]
    rule.is_active = True

    try:
        rule_versioning_service.restore(rule_id)
    except RuleVersioningError:
        pass

    return {
        "message": f"Rule '{rule_id}' was successfully restored.",
        "rule_id": rule_id,
        "is_active": True,
    }


@router.get("/{rule_id}/versions")
async def get_rule_versions(rule_id: str):
    history = rule_versioning_service.get_history(rule_id)

    if not history and rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    summary = rule_versioning_service.history_summary(rule_id)

    return summary


@router.get("/{rule_id}/versions/{version}")
async def get_rule_version(rule_id: str, version: int):
    if rule_id not in INGESTED_RULES and not rule_versioning_service.get_history(rule_id):
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    record = rule_versioning_service.get_version_number(rule_id, version)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Version {version} for rule '{rule_id}' not found",
        )

    return {
        "rule_id": record.rule_id,
        "version": record.version,
        "content_hash": record.content_hash,
        "title": record.title,
        "rule_format": record.rule_format,
        "status": record.status,
        "is_latest": record.is_latest,
        "parent_content_hash": record.parent_content_hash,
        "change_log": record.change_log,
        "recorded_at": record.recorded_at,
    }
