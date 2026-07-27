class ConnectorTransientError(Exception):
    """Exception raised for transient issues that can be retried (e.g. rate limits, 5xx server errors)."""
    pass

class ConnectorPermanentError(Exception):
    """Exception raised for permanent failures that should not be retried (e.g. invalid credentials, 4xx client errors)."""
    pass
