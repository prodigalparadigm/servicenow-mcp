"""Entry point for ``python -m servicenow_mcp`` and the console script.

Runs over the MCP stdio transport, which means **stdout is the protocol
channel**. Nothing in this package writes there: configuration errors, startup
banners, and the audit trail all go to stderr, because one stray byte on stdout
breaks the JSON-RPC framing and the client disconnects with an opaque error.
"""

from __future__ import annotations

import sys

from .app import build_from_env
from .config import Settings
from .errors import ConfigurationError


def main() -> int:
    """Start the server on stdio. Returns a process exit code."""
    try:
        settings = Settings.from_env()
    except ConfigurationError as exc:
        print(f"servicenow-mcp: configuration error: {exc}", file=sys.stderr)
        print(
            "servicenow-mcp: see .env.example for the full list of settings.",
            file=sys.stderr,
        )
        return 2

    app = build_from_env()
    mode = "read-only" if settings.read_only else "READ-WRITE"
    print(
        f"servicenow-mcp: {settings.instance_url} "
        f"[{mode}, auth={settings.auth_mode.value}, "
        f"cap={settings.max_records} records/call]",
        file=sys.stderr,
    )
    try:
        app.server.run(transport="stdio")
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        return 130
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
