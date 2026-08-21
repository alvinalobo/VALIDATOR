from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from importlib import import_module

from app.connector.base_connector import ConnectorRegistry
from app.services.health_monitor import (
    monitor,
    ConnectorHealthStatus,
)


router = APIRouter(
    prefix="/api/v2/connectors",
    tags=["Connectors"],
)


class RegisterConnectorRequest(BaseModel):
    vendor: str
    module: str
    class_name: str


class RecordQueryRequest(BaseModel):
    latency: float
    success: bool


class RecordConnectionStatusRequest(BaseModel):
    available: bool


@router.post("/register", status_code=201)
async def register_connector(
    request: RegisterConnectorRequest,
):
    """
    Register a connector dynamically.
    """

    try:
        try:
            ConnectorRegistry.get(request.vendor)

            raise HTTPException(
                status_code=409,
                detail=(
                    f"Connector '{request.vendor}' "
                    "already registered."
                ),
            )

        except KeyError:
            pass

        module = import_module(request.module)

        connector_cls = getattr(
            module,
            request.class_name,
        )

        ConnectorRegistry.register(
            request.vendor,
            connector_cls,
        )

        return {
            "success": True,
            "message": "Connector registered successfully.",
            "vendor": request.vendor,
            "connector": request.class_name,
        }

    except HTTPException:
        raise

    except ModuleNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Module '{request.module}' not found."
            ),
        )

    except AttributeError:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Class '{request.class_name}' not found."
            ),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get("/registered")
async def registered_connectors():
    return {
        "count": len(
            ConnectorRegistry._connectors
        ),
        "vendors": list(
            ConnectorRegistry._connectors.keys()
        ),
    }


@router.get(
    "/health/{connector_id}",
    response_model=ConnectorHealthStatus,
)
async def connector_health(
    connector_id: str,
):
    """
    Return the current health metrics for a connector.
    """

    health = monitor.get_health(
        connector_id
    )

    if health is None:
        raise HTTPException(
            status_code=404,
            detail="Connector health not found.",
        )

    return health


@router.get(
    "/health",
    response_model=list[ConnectorHealthStatus],
)
async def all_connector_health():
    """
    Return current health metrics for all connectors.
    """

    return monitor.get_all_health()


@router.post(
    "/health/{connector_id}/query",
)
async def record_connector_query(
    connector_id: str,
    request: RecordQueryRequest,
):
    """
    Record one connector query result.

    latency is measured in seconds.
    success indicates whether the query succeeded.
    """

    if connector_id not in monitor.metrics:
        raise HTTPException(
            status_code=404,
            detail="Connector health not found.",
        )

    if request.latency < 0:
        raise HTTPException(
            status_code=400,
            detail="Latency cannot be negative.",
        )

    monitor.record_query(
        connector_id=connector_id,
        latency=request.latency,
        success=request.success,
    )

    return {
        "success": True,
        "connector_id": connector_id,
    }


@router.post(
    "/health/{connector_id}/connection",
)
async def record_connector_connection(
    connector_id: str,
    request: RecordConnectionStatusRequest,
):
    """
    Record connector availability.
    """

    if connector_id not in monitor.metrics:
        raise HTTPException(
            status_code=404,
            detail="Connector health not found.",
        )

    monitor.record_connection_status(
        connector_id=connector_id,
        available=request.available,
    )

    return {
        "success": True,
        "connector_id": connector_id,
        "available": request.available,
    }


@router.post(
    "/health/{connector_id}/register",
)
async def register_connector_health(
    connector_id: str,
    vendor: str,
    product: str,
):
    """
    Start health monitoring for a connector.
    """

    monitor.register_connector(
        connector_id=connector_id,
        vendor=vendor,
        product=product,
    )

    return {
        "success": True,
        "connector_id": connector_id,
        "vendor": vendor,
        "product": product,
    }


@router.get("/{vendor}")
async def connector_info(
    vendor: str,
):
    try:
        connector = ConnectorRegistry.get(
            vendor
        )

        return {
            "vendor": vendor,
            "connector_class": connector.__name__,
        }

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Connector not found.",
        )
