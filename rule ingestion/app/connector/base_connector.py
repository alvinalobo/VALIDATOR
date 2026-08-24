from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Type, Callable, TypeVar

from pydantic import BaseModel, Field

from app.connector.resilience import ConnectorResilience
T = TypeVar("T")


class ConnectorConfig(BaseModel):
    connector_id: str
    vendor: str  # e.g., 'splunk', 'sentinel', 'elastic', 'qradar', 'crowdstrike'
    product: str
    credentials: Dict[str, Any] = Field(default_factory=dict)
    scope: Dict[str, Any] = Field(default_factory=dict)


class BaseConnector(ABC):
    """
    Base interface for all security connectors.

    Provides:
        - Common connector configuration
        - Poll timestamp tracking
        - Centralized resilience execution
    """

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self._last_poll_ts: Optional[float] = None

        # Centralized resilience layer.
        # Each connector instance gets its own circuit breaker.
        self.resilience = ConnectorResilience()

    @abstractmethod
    def query(
        self,
        query_str: str,
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
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

    def execute_with_resilience(
        self,
        operation: Callable[..., T],
        *args: Any,
        fallback: Optional[Callable[..., T]] = None,
        max_attempts: Optional[int] = None,
        **kwargs: Any,
    )-> T:
        """
    Execute a connector operation through the centralized
    resilience layer.
    """

        return self.resilience.execute(
            operation,
            *args,
            fallback=fallback,
            max_attempts=max_attempts,
            **kwargs,
        )

    def reset_resilience(self) -> None:
        """
        Manually reset the connector's circuit breaker.
        """
        self.resilience.reset()

    @property
    def circuit_state(self):
        """
        Return the current circuit breaker state.
        """
        return self.resilience.state

    @property
    def circuit_failure_count(self) -> int:
        """
        Return the current consecutive circuit breaker failure count.
        """
        return self.resilience.failure_count


class ConnectorRegistry:
    """
    Registry for connector implementations.
    """

    _connectors: Dict[str, Type[BaseConnector]] = {}

    @classmethod
    def register(
        cls,
        vendor: str,
        connector_cls: Type[BaseConnector],
    ):
        cls._connectors[vendor.lower()] = connector_cls

    @classmethod
    def get(cls, vendor: str) -> Type[BaseConnector]:
        vendor_key = vendor.lower()

        if vendor_key not in cls._connectors:
            raise KeyError(
                f"No connector registered for vendor '{vendor}'"
            )

        return cls._connectors[vendor_key]