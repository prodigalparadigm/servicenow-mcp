"""Composition root: wires settings into a ready-to-run MCP server."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import httpx
from mcp.server import MCPServer

from .audit import AuditLogger
from .auth import build_auth_provider
from .client import ServiceNowClient
from .config import Settings
from .server import build_server
from .service import ServiceNowService
from .transport import ServiceNowTransport

__all__ = ["Application", "build_application"]


@dataclass(slots=True)
class Application:
    """The assembled object graph, kept together so it can be closed cleanly."""

    settings: Settings
    server: MCPServer
    service: ServiceNowService

    async def aclose(self) -> None:
        await self.service.aclose()


def build_application(
    settings: Settings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    audit: AuditLogger | None = None,
) -> Application:
    """Assemble the server.

    Args:
        settings: Validated configuration.
        transport: Optional httpx transport. Tests inject an in-memory fake
            ServiceNow here, which is why the whole suite runs offline while
            still exercising the real request path -- headers, retries, auth,
            and query encoding all execute unchanged.
        audit: Optional audit sink; defaults to the configured path or stderr.

    Returns:
        An :class:`Application` whose ``server`` is ready to run.
    """
    http_client = httpx.AsyncClient(
        transport=transport,
        timeout=settings.timeout_seconds,
        follow_redirects=False,
    )
    auth_provider = build_auth_provider(settings, http_client)
    snow_transport = ServiceNowTransport(
        settings, http_client=http_client, auth_provider=auth_provider
    )
    client = ServiceNowClient(settings, snow_transport)
    audit_logger = audit or AuditLogger.from_path(
        settings.audit_log_path, actor=settings.actor
    )
    service = ServiceNowService(settings, client, audit_logger)
    server = build_server(settings, service)
    return Application(settings=settings, server=server, service=service)


def build_from_env(env: Mapping[str, str] | None = None) -> Application:
    """Convenience wrapper reading configuration from the environment."""
    return build_application(Settings.from_env(env))
