"""Entry point for ``python -m servicenow_mcp`` and the console script.

Runs over the MCP stdio transport, which means **stdout is the protocol
channel**. Nothing in this package writes there: configuration errors, startup
banners, and the audit trail all go to stderr, because one stray byte on stdout
breaks the JSON-RPC framing and the client disconnects with an opaque error.
"""

from __future__ import annotations

import asyncio
import sys

from .app import Application, build_application
from .config import Settings
from .errors import ConfigurationError


async def _serve(app: Application) -> None:
    """Serve stdio until the client disconnects, then release the HTTP client.

    ``MCPServer.run`` is synchronous and owns its own event loop, so it is not
    used here: closing the ``httpx`` client has to happen on the loop its
    connections were opened on, and that loop must still be alive.
    """
    try:
        await app.server.run_stdio_async()
    finally:
        await app.aclose()


def main() -> int:
    """Start the server on stdio. Returns a process exit code."""
    try:
        # Read and validate the environment exactly once, then build from the
        # object -- so the running server cannot disagree with the banner.
        settings = Settings.from_env()
        app = build_application(settings)
    except ConfigurationError as exc:
        print(f"servicenow-mcp: configuration error: {exc}", file=sys.stderr)
        print(
            "servicenow-mcp: see .env.example for the full list of settings.",
            file=sys.stderr,
        )
        return 2

    mode = "read-only" if settings.read_only else "READ-WRITE"
    print(
        f"servicenow-mcp: {settings.instance_url} "
        f"[{mode}, auth={settings.auth_mode.value}, "
        f"cap={settings.max_records} records/call]",
        file=sys.stderr,
    )
    try:
        asyncio.run(_serve(app))
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        return 130
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
