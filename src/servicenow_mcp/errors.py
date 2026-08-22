"""Exception hierarchy for the ServiceNow MCP server.

Every error a tool can surface derives from :class:`ServiceNowMCPError` so the
MCP layer can convert failures into a single, predictable shape instead of
leaking ``httpx`` internals to the model.
"""

from __future__ import annotations

__all__ = [
    "ServiceNowMCPError",
    "ConfigurationError",
    "ReadOnlyModeError",
    "TransportError",
    "AuthenticationError",
    "RateLimitedError",
    "ServiceNowAPIError",
    "MalformedResponseError",
    "RecordNotFoundError",
]


class ServiceNowMCPError(Exception):
    """Base class for every error raised by this package."""


class ConfigurationError(ServiceNowMCPError):
    """Settings are missing, contradictory, or unsafe."""


class ReadOnlyModeError(ServiceNowMCPError):
    """A mutating operation was attempted while the server is read-only."""


class TransportError(ServiceNowMCPError):
    """The request could not be completed: timeout, DNS, TLS, reset socket.

    Raised only after the retry policy has given up.
    """


class AuthenticationError(ServiceNowMCPError):
    """Credentials were rejected (401/403) or a token could not be obtained."""


class RateLimitedError(ServiceNowMCPError):
    """The instance returned 429 and the retry budget was exhausted.

    ``retry_after`` carries the last server-advertised backoff in seconds, if
    the instance provided one, so a caller can decide whether to reschedule.
    """

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ServiceNowAPIError(ServiceNowMCPError):
    """The instance returned a structured error envelope or a 4xx/5xx status."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


class MalformedResponseError(ServiceNowMCPError):
    """A 2xx response did not contain the payload the Table API documents.

    Seen in the wild when a reverse proxy, SSO portal, or WAF interposes an
    HTML page on an otherwise successful-looking response.
    """


class RecordNotFoundError(ServiceNowMCPError):
    """A lookup by number, sys_id, or name matched no record."""
