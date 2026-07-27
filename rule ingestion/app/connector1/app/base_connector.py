from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Type
from pydantic import BaseModel

class ConnectorConfig(BaseModel):
    connector_id: str
    vendor: str # e.g., 'splunk', 'sentinel', 'elastic', 'qradar', 'crowdstrike'
    product: str
    credentials: Dict[str, Any] = {}
    scope: Dict[str, Any] = {}

class BaseConnector(ABC):
    def __init__(self, config: ConnectorConfig):
        self.config = config
        self._last_poll_ts: Optional[float] = None

    @abstractmethod
    def query(self, query_str: str, time_range: tuple) -> List[Dict[str, Any]]:
        """Execute a read-only query. Returns raw results."""
        pass

    @abstractmethod
    def poll(self) -> List[Dict[str, Any]]:
        """Pull new events since last poll. READ-ONLY."""
        pass

    @abstractmethod
    def validate_connection(self) -> bool:
        """Verify credentials work. READ-ONLY."""
        pass

class ConnectorRegistry:
    _connectors: Dict[str, Type[BaseConnector]] = {}

    @classmethod
    def register(cls, vendor: str, connector_cls: Type[BaseConnector]):
        cls._connectors[vendor.lower()] = connector_cls

    @classmethod
    def get(cls, vendor: str) -> Type[BaseConnector]:
        vendor_key = vendor.lower()
        if vendor_key not in cls._connectors:
            raise KeyError(f"No connector registered for vendor '{vendor}'")
        return cls._connectors[vendor_key]
