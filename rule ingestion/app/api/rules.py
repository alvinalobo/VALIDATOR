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
