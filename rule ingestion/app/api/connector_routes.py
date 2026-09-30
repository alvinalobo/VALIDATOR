from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from importlib import import_module

from app.connector.base_connector import ConnectorRegistry
from app.services.health_monitor import (
    monitor,
    ConnectorHealthStatus,
)
from app.security.security import get_current_claims


router = APIRouter(
    prefix="/api/v2/connectors",
    tags=["Connectors"],
    dependencies=[Depends(get_current_claims)],
)


@router.get("/ownership")
async def registry_ownership():
    """The canonical connector registry is owned by Alpha."""
    return {
        "owner": "alpha",
        "service": "rule-ingestion",
        "canonical_table": "connectors",
        "canonical_api": "/api/v2/connectors",
        "status": "canonical",
    }


class RegisterConnectorRequest(BaseModel):
    vendor: str
    module: str
    class_name: str
