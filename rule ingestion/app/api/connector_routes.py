from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from importlib import import_module

from connector.base_connector import ConnectorRegistry

router = APIRouter(
    prefix="/api/v2/connectors",
    tags=["Connectors"]
)


class RegisterConnectorRequest(BaseModel):
    vendor: str
    module: str
    class_name: str


@router.post("/register", status_code=201)
async def register_connector(request: RegisterConnectorRequest):
    """
    Register a connector dynamically.

    Example:
    {
        "vendor":"splunk",
        "module":"connector.splunk_connector",
        "class_name":"SplunkConnector"
    }
    """

    try:
        # Duplicate check
        try:
            ConnectorRegistry.get(request.vendor)
            raise HTTPException(
                status_code=409,
                detail=f"Connector '{request.vendor}' already registered."
            )
        except KeyError:
            pass

        # Dynamic import
        module = import_module(request.module)
        connector_cls = getattr(module, request.class_name)

        ConnectorRegistry.register(
            request.vendor,
            connector_cls
        )

        return {
            "success": True,
            "message": "Connector registered successfully.",
            "vendor": request.vendor,
            "connector": request.class_name
        }

    except HTTPException:
        raise

    except ModuleNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Module '{request.module}' not found."
        )

    except AttributeError:
        raise HTTPException(
            status_code=404,
            detail=f"Class '{request.class_name}' not found."
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@router.get("/registered")
async def registered_connectors():

    return {
        "count": len(ConnectorRegistry._connectors),
        "vendors": list(ConnectorRegistry._connectors.keys())
    }


@router.get("/{vendor}")
async def connector_info(vendor: str):

    try:
        connector = ConnectorRegistry.get(vendor)

        return {
            "vendor": vendor,
            "connector_class": connector.__name__
        }

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Connector not found."
        )

   