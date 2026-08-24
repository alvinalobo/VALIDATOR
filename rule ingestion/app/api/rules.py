from fastapi import APIRouter, HTTPException
from typing import List, Dict
import os
import hashlib
import shutil
import git
from app.models.rule_models import RuleIngestRequest, ParsedRule
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
        
        parsed = None
        if f.endswith('.yml') or f.endswith('.yaml'):
            parsed = parse_sigma(raw)
        elif f.endswith('.kql'):
            parsed = parse_kql(raw)
            
        if parsed:
            rules.append(parsed)
            # Store in database
            INGESTED_RULES[parsed.rule_id] = parsed
            
    return rules
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
    # If the rule is DET-002, return mock active checks
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
