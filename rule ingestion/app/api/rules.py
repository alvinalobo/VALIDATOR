from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Optional
import os
import hashlib
import shutil
import git

from app.models.rule_models import RuleIngestRequest, ParsedRule, RuleFormatEnum
from app.services.sigma_parser import parse_sigma_rule
from app.services.kql_parser import parse_kql_rule

router = APIRouter(prefix="/api/v2/rules", tags=["rules"])

# In-memory database of parsed rules
INGESTED_RULES: Dict[str, ParsedRule] = {}

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

@router.get("/search", response_model=List[ParsedRule])
async def search_rules(
    q: str = Query(default="", description="Search term (matches title, description, tags)"),
    status: str = Query(default=None, description="Filter by status: active, deprecated"),
    severity: str = Query(default=None, description="Filter by severity: low, medium, high, critical"),
    mitre_technique: str = Query(default=None, description="Filter by MITRE technique ID (e.g. T1059)"),
    rule_format: str = Query(default=None, description="Filter by format: sigma, kql, yara"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
    sort_by: str = Query(default="created_at", description="Sort field: created_at, updated_at, title"),
    sort_order: str = Query(default="desc", description="Sort direction: asc, desc"),
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
        if status.lower() == "active":
            results = [r for r in results if r.is_active]
        elif status.lower() == "deprecated":
            results = [r for r in results if not r.is_active]

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
        results = [
            r for r in results
            if r.rule_format and r.rule_format.value == rule_format.lower()
        ]

    # --- Sorting ---
    sort_fields = {
        "created_at": lambda r: r.created_at,
        "updated_at": lambda r: r.updated_at,
        "title": lambda r: (r.title or "").lower(),
    }
    sort_fn = sort_fields.get(sort_by, sort_fields["created_at"])
    reverse = sort_order.lower() == "desc"
    results.sort(key=sort_fn, reverse=reverse)

    # --- Pagination ---
    total = len(results)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = results[start:end]

    return paginated

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
    return {
        "message": f"Rule '{rule_id}' was successfully deprecated.",
        "rule_id": rule_id,
        "is_active": False
    }

@router.get("/{rule_id}/dependencies")
async def get_rule_dependencies(rule_id: str):
    if rule_id not in INGESTED_RULES:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    
    # Mocking rule dependencies (historical validation runs that used this rule)
    if rule_id == "b2345678-9abc-def0-1234-56789abcdef0":
        return {
            "rule_id": rule_id,
            "dependencies": [
                {"run_id": "run-001", "action_id": "act-501", "status": "active"},
                {"run_id": "run-002", "action_id": "act-502", "status": "completed"}
            ]
        }
    
    return {
        "rule_id": rule_id,
        "dependencies": []
    }
