import math
from math import ceil
from fastapi import APIRouter, HTTPException, Query, Response
from typing import List, Dict, Optional, Union
import os
import hashlib
import shutil
import git
from copy import deepcopy
from pydantic import BaseModel, Field
from typing import Any
from app.models.rule_models import RuleIngestRequest, ParsedRule, RuleFormatEnum, PaginatedRuleResponse
from app.services.sigma_parser import parse_sigma_rule
from app.services.kql_parser import parse_kql_rule
from app.services.rule_versioning import rule_versioning_service, RuleVersioningError
from app.services.rule_dependency_tracker import (
    RuleDependencyTracker,
    RuleHasDependentsError,
)
from dataclasses import asdict
router = APIRouter(prefix="/api/v2/rules", tags=["rules"])
# Tracks which validation runs / re-validation runs / actions used which rule
# version, so a rule can be retired without silently stranding a verdict's
# audit trail (W7).
dependency_tracker = RuleDependencyTracker()

# Content-addressed parse cache (W13). A large rule repository (1000+ rules)
# routinely contains the same content in several places — vendor packs, forks,
# copied directories. Parsing dominates ingest cost (~10 ms/rule with pySigma),
# so identical bytes are parsed once and the stored result is returned as a copy.
_PARSE_CACHE: Dict[str, Any] = {}
_PARSE_CACHE_MAX_ENTRIES = 5000


def _parse_rule_content(raw: str, file_path: str):
    """
    Parse one rule file's contents, memoised on (content hash, extension).

    Returns (parsed_dict, rule_format, error_msg).

    Identical bytes always parse to an identical result, so the cache is exact
    rather than heuristic. Results are deep-copied on the way in and out so
    that two rules sharing the same source content never alias the same
    mutable dicts.
    """
    suffix = os.path.splitext(file_path)[1].lower()
    content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    cache_key = (content_hash, suffix)

    cached = _PARSE_CACHE.get(cache_key)
    if cached is not None:
        return deepcopy(cached[0]), cached[1], cached[2]

    parsed_dict = None
    rule_format = None
    error_msg = None
    try:
        if suffix in (".yml", ".yaml"):
            parsed_dict = parse_sigma_rule(raw)
            rule_format = RuleFormatEnum.SIGMA
        elif suffix == ".kql":
            parsed_dict = parse_kql_rule(raw)
            rule_format = RuleFormatEnum.KQL
        else:
            rule_format = RuleFormatEnum.SIGMA
    except Exception as e:
        error_msg = str(e)
        rule_format = (
            RuleFormatEnum.SIGMA if suffix in (".yml", ".yaml") else RuleFormatEnum.KQL
        )

    if len(_PARSE_CACHE) >= _PARSE_CACHE_MAX_ENTRIES:
        _PARSE_CACHE.clear()
    _PARSE_CACHE[cache_key] = (deepcopy(parsed_dict), rule_format, error_msg)

    return parsed_dict, rule_format, error_msg
# In-memory database of parsed rules
INGESTED_RULES: Dict[str, ParsedRule] = {}
class RuleSearchResponse(BaseModel):
    items: List[ParsedRule]
    total: int
    page: int
    page_size: int
    total_pages: int


class RuleDependencyRequest(BaseModel):
    """Recorded by the Validation Engine (Pod Beta) whenever a rule version
    is actually executed against evidence."""

    dependent_type: str = Field(
        ...,
        description="Dependent kind: 'validation_run', 'revalidation_run' or 'action'",
    )
    dependent_id: str = Field(..., description="Identifier of the dependent")
    metadata: Optional[Dict[str, str]] = Field(
        default=None, description="Optional extra context for the dependency record"
    )


class RuleDependencyResponse(BaseModel):
    rule_id: str
    dependent_count: int
    safe_to_delete: bool
    report: str
    dependencies: List[Dict[str, Any]] = Field(default_factory=list)
def clone_repo(repo_url: str, branch: str = 'main', depth: Optional[int] = 1) -> str:
    # If repo_url is a local path, use it directly
    if os.path.exists(repo_url) and os.path.isdir(repo_url):
        return os.path.abspath(repo_url)
        
    # Generate unique directory name
    h = hashlib.sha256(f"{repo_url}#{branch}".encode('utf-8')).hexdigest()[:12]
    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".cloned_repos"))
    os.makedirs(workspace_dir, exist_ok=True)
    repo_path = os.path.join(workspace_dir, f"{h}_{branch}")
    
    if os.path.exists(repo_path):
        try:
            repo = git.Repo(repo_path)
            if depth:
                repo.remotes.origin.fetch(depth=depth)
            else:
                repo.remotes.origin.fetch()
            repo.git.checkout(branch)
            repo.git.reset('--hard', f'origin/{branch}')
            return repo_path
        except Exception:
            shutil.rmtree(repo_path, ignore_errors=True)
            
    clone_kwargs = {"branch": branch}
    if depth:
        clone_kwargs["depth"] = depth
        clone_kwargs["single_branch"] = True
    git.Repo.clone_from(repo_url, repo_path, **clone_kwargs)
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
        
        parsed_dict, rule_format, error_msg = _parse_rule_content(raw, f)
            
        if parsed_dict:
            raw_data = parsed_dict.get("raw", {})
            tags = [str(t) for t in raw_data.get("tags", [])] if isinstance(raw_data.get("tags"), list) else []
            severity = raw_data.get("severity") or raw_data.get("level")
            
            parsed = ParsedRule(
                rule_id=parsed_dict.get("rule_id") or "UNKNOWN",
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
            # Store in database
            INGESTED_RULES[parsed.rule_id] = parsed
            # Record the full version history, addressed by content hash, so a
            # verdict produced by an older revision stays reproducible after the
            # rule is edited (W7). Re-ingesting identical content is a no-op.
            rule_versioning_service.record_version(
                rule_id=parsed.rule_id,
                content_hash=parsed.content_hash,
                title=parsed.title,
                rule_format=parsed.rule_format.value,
            )
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
    return INGESTED_RULES[rule_id]
@router.post("/{rule_id}/deprecate")
async def deprecate_rule(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    rule = INGESTED_RULES[rule_id]
    rule.is_active = False

    # Retire the rule without breaking reproducibility: the versioning service
    # keeps every historical content hash addressable, and existing dependents
    # are reported rather than blocked (deprecation must not break the verdicts
    # that already reference this rule) — W7.
    try:
        rule_versioning_service.record_version(
            rule_id=rule_id,
            content_hash=rule.content_hash,
            title=rule.title,
            rule_format=rule.rule_format.value,
        )
        rule_versioning_service.deprecate(rule_id)
    except RuleVersioningError:
        # Rule predates version tracking (e.g. seeded directly into
        # INGESTED_RULES); deprecation still succeeds in the legacy store.
        pass

    dependents = dependency_tracker.get_dependents(rule_id)
    return {
        "message": f"Rule '{rule_id}' was successfully deprecated.",
        "rule_id": rule_id,
        "is_active": False,
        "dependent_count": len(dependents),
        "warning": (
            f"{len(dependents)} dependent validation run(s) still reference "
            "this rule; historical verdicts remain reproducible via the "
            "content-addressed version store."
            if dependents
            else None
        ),
    }
@router.get("/{rule_id}/dependencies")
async def get_rule_dependencies(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    
    dependents = dependency_tracker.get_dependents(rule_id)
    return {
        "rule_id": rule_id,
        "dependent_count": len(dependents),
        "safe_to_delete": not dependents,
        "report": dependency_tracker.dependency_report(rule_id),
        "dependencies": [asdict(dep) for dep in dependents],
    }


@router.post("/{rule_id}/dependencies", status_code=201)
async def record_rule_dependency(rule_id: str, request: RuleDependencyRequest):
    """
    Record that a rule version was used by a validation run / re-validation run
    / action (W7). The Validation Engine calls this when it executes a rule, so
    the dependency graph reflects real usage rather than ingestion alone.
    """
    if request.dependent_type not in {
        "validation_run",
        "revalidation_run",
        "action",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "dependent_type must be one of: validation_run, "
                "revalidation_run, action"
            ),
        )

    dependency_tracker.record_usage(
        rule_id=rule_id,
        dependent_type=request.dependent_type,
        dependent_id=request.dependent_id,
        metadata=request.metadata,
    )

    return {
        "rule_id": rule_id,
        "dependent_type": request.dependent_type,
        "dependent_id": request.dependent_id,
        "dependent_count": len(dependency_tracker.get_dependents(rule_id)),
    }


@router.get("/{rule_id}/impact")
async def rule_retirement_impact(rule_id: str):
    """
    Answers "is it safe to delete/edit this rule?" before a detection engineer
    does it, returning the full dependent list rather than a bare boolean (W7).
    """
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    dependents = dependency_tracker.get_dependents(rule_id)
    return {
        "rule_id": rule_id,
        "safe_to_delete": not dependents,
        "safe_to_edit": not dependents,
        "dependent_count": len(dependents),
        "report": dependency_tracker.dependency_report(rule_id),
        "dependencies": [asdict(dep) for dep in dependents],
    }


@router.get("/{rule_id}/versions")
async def get_rule_versions(rule_id: str):
    """
    Full content-addressed version history for a rule (W7): every revision that
    has ever existed, which one is current, and the current status. Superseded
    revisions stay addressable so past verdicts remain explainable.
    """
    summary = rule_versioning_service.history_summary(rule_id)
    if summary["version_count"] == 0 and rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    return summary


@router.get("/{rule_id}/versions/{version}")
async def get_rule_version(rule_id: str, version: int):
    """Resolve one specific historical version of a rule."""
    record = rule_versioning_service.get_version_number(rule_id, version)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Rule '{rule_id}' has no version {version}",
        )
    return asdict(record)


@router.post("/{rule_id}/restore")
async def restore_rule(rule_id: str):
    """Reinstate a deprecated rule without discarding its version history (W7)."""
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

    INGESTED_RULES[rule_id].is_active = True
    try:
        rule_versioning_service.restore(rule_id)
    except RuleVersioningError:
        pass

    return {
        "message": f"Rule '{rule_id}' was successfully restored.",
        "rule_id": rule_id,
        "is_active": True,
    }
