class ConnectorError(Exception):
    """Base class for all connector failures."""


class ConnectorTransientError(ConnectorError):
    """A failure that might succeed if retried: network blip, timeout,
    5xx server error, rate limit (429). Safe to retry with backoff."""


class ConnectorPermanentError(ConnectorError):
    """A failure retrying won't fix: bad credentials (401/403), a
    malformed query (400), a vendor telling you the resource doesn't
    exist (404). Raised immediately, no retry."""