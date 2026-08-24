class ConnectorError(Exception):
    """Base class for all connector-related failures."""


class ConnectorTransientError(ConnectorError):
    """
    A temporary connector failure that may succeed if retried.

    Examples:
        - Network interruption
        - Connection timeout
        - Read timeout
        - HTTP 429 rate limit
        - HTTP 5xx server error
    """


class ConnectorPermanentError(ConnectorError):
    """
    A connector failure that retrying will not normally fix.

    Examples:
        - Invalid credentials
        - HTTP 400
        - HTTP 401
        - HTTP 403
        - HTTP 404
        - Invalid connector configuration
        - Malformed query
    """


class ConnectorTimeoutError(ConnectorTransientError):
    """Raised when a connector request times out."""


class ConnectorConnectionError(ConnectorTransientError):
    """Raised when a connector cannot establish a connection."""


class ConnectorRateLimitError(ConnectorTransientError):
    """Raised when the remote endpoint rate-limits the connector."""


class ConnectorServerError(ConnectorTransientError):
    """Raised when the remote endpoint returns an HTTP 5xx error."""


class ConnectorAuthenticationError(ConnectorPermanentError):
    """Raised when connector authentication or authorization fails."""


class ConnectorBadRequestError(ConnectorPermanentError):
    """Raised when the remote endpoint rejects the request as invalid."""


class ConnectorNotFoundError(ConnectorPermanentError):
    """Raised when the requested resource or endpoint does not exist."""


class ConnectorConfigurationError(ConnectorPermanentError):
    """Raised when connector configuration is invalid."""


class ConnectorResponseError(ConnectorPermanentError):
    """Raised when the connector receives an invalid or unexpected response."""


class ConnectorFallbackError(ConnectorError):
    """
    Raised when the connector's fallback mechanism also fails.
    """