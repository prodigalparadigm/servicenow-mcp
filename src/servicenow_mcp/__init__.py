"""A Model Context Protocol server for ServiceNow ITSM.

Exposes incident search and retrieval, incident creation and annotation,
assignment-group lookup, and read-only CMDB ownership lookup as MCP tools,
with pagination caps, retry/backoff, field allowlists, a read-only mode, and
structured audit logging.
"""

from __future__ import annotations

from .app import Application, build_application, build_from_env
from .config import AuthMode, Settings
from .errors import (
    AuthenticationError,
    ConfigurationError,
    MalformedResponseError,
    RateLimitedError,
    ReadOnlyModeError,
    RecordNotFoundError,
    ServiceNowAPIError,
    ServiceNowMCPError,
    TransportError,
)

__version__ = "0.1.0"

__all__ = [
    "Application",
    "AuthMode",
    "AuthenticationError",
    "ConfigurationError",
    "MalformedResponseError",
    "RateLimitedError",
    "ReadOnlyModeError",
    "RecordNotFoundError",
    "ServiceNowAPIError",
    "ServiceNowMCPError",
    "Settings",
    "TransportError",
    "__version__",
    "build_application",
    "build_from_env",
]
