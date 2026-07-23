from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from services.connector_framework.app.base_connector import ConnectorConfig, ConnectorRegistry
from services.connector_framework.app.health_monitor import monitor, ConnectorHealthStatus
import services.connector_framework.app.connectors.splunk_connector

router = APIRouter(prefix="/api/v2/connectors", tags=["connectors"])
CONNECTOR_INSTANCES: Dict[str, Any] = {}

@router.post("/register", status_code=201)
async def register_connector(config: ConnectorConfig):
    try:
        connector_cls = ConnectorRegistry.get(config.vendor)
        instance = connector_cls(config)
        
        CONNECTOR_INSTANCES[config.connector_id] = instance
        monitor.register_connector(config.connector_id, config.vendor, config.product)
        
        is_available = instance.validate_connection()
        monitor.record_connection_status(config.connector_id, is_available)
        
        return {
            "message": f"Connector '{config.connector_id}' registered successfully",
            "connector_id": config.connector_id,
            "connected": is_available
        }
    except KeyError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@router.get("/health", response_model=List[ConnectorHealthStatus])
async def get_connectors_health():
    for cid, instance in CONNECTOR_INSTANCES.items():
        try:
            is_available = instance.validate_connection()
            monitor.record_connection_status(cid, is_available)
        except Exception:
            monitor.record_connection_status(cid, False)
            
    return monitor.get_all_health()
