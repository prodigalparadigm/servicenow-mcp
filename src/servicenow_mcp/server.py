"""MCP protocol layer: registers the service's methods as MCP tools.

Written against the ``mcp`` Python SDK 2.x, where the high-level server class
is ``mcp.server.MCPServer`` (it was named ``FastMCP`` in 1.x) and model fields
are snake_case (``input_schema``, ``is_error``).

The module stays deliberately thin. All behaviour lives in
:mod:`servicenow_mcp.service`, so the parts worth reviewing do not depend on
the SDK's surface, and an SDK upgrade touches one file.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from .config import Settings
from .service import ServiceNowService

__all__ = ["build_server", "SERVER_INSTRUCTIONS"]

SERVER_INSTRUCTIONS = """\
Tools for a ServiceNow ITSM instance: incidents, assignment groups, and CMDB \
ownership.

Working notes:
- Results are paginated. Read `has_more` and pass `next_offset` back in rather \
than raising `limit`; a single call is hard-capped server-side.
- Incident records come back as a curated field projection, not the full row. \
`search_incidents` returns a triage summary; call `get_incident` for the \
narrative fields of one incident.
- The server may be in read-only mode, in which case no mutating tool is \
offered. Call `server_info` first if you need to know before planning a write.
- `create_incident` accepts a `correlation_id`. Pass a stable one derived from \
the triggering event so a retry returns the existing incident instead of \
opening a duplicate.
"""


def _read_only_annotations(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    )


def build_server(settings: Settings, service: ServiceNowService) -> MCPServer:
    """Construct the MCP server and register the tools this config allows.

    Mutating tools are not registered at all when ``settings.read_only`` is
    true. The service refuses them independently -- a client can call a tool
    name it was never shown -- but omitting them keeps the model from planning
    around an action it will not be permitted to take.
    """
    server = MCPServer(
        name="servicenow",
        title="ServiceNow ITSM",
        version="0.1.0",
        instructions=SERVER_INSTRUCTIONS,
    )

    @server.tool(
        name="server_info",
        description=(
            "Report this server's operating mode: read-only or writable, which "
            "instance it targets, the per-call record cap, and which incident "
            "fields are returned. Call before planning a write."
        ),
        annotations=_read_only_annotations("Server info"),
    )
    async def server_info() -> dict[str, Any]:
        return await service.server_info()

    @server.tool(
        name="search_incidents",
        description=(
            "Search incidents with optional filters and pagination. Returns a "
            "summary projection of each match plus has_more/next_offset. All "
            "filters are optional and combined with AND. Use offset to page; "
            "a single call is capped server-side."
        ),
        annotations=_read_only_annotations("Search incidents"),
    )
    async def search_incidents(
        text: str | None = None,
        state: str | None = None,
        priority: int | None = None,
        assignment_group: str | None = None,
        assigned_to: str | None = None,
        caller: str | None = None,
        category: str | None = None,
        active_only: bool | None = None,
        opened_after: str | None = None,
        extra_query: str | None = None,
        order_by: str = "-sys_updated_on",
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Search the incident table.

        Args:
            text: Substring matched against short_description.
            state: State label ("new", "in progress", "resolved") or number.
            priority: 1-5, where 1 is most severe.
            assignment_group: Exact group name.
            assigned_to: Assignee's ServiceNow user_name.
            caller: Caller's ServiceNow user_name.
            category: Exact category value, e.g. "network".
            active_only: True for open incidents only.
            opened_after: ISO timestamp, e.g. "2026-01-01 00:00:00".
            extra_query: Raw ServiceNow encoded query appended verbatim, for
                filters the typed parameters do not cover.
            order_by: Sort field; prefix with "-" for descending.
            limit: Records wanted, capped server-side.
            offset: Starting record offset for pagination.
        """
        return await service.search_incidents(
            text=text,
            state=state,
            priority=priority,
            assignment_group=assignment_group,
            assigned_to=assigned_to,
            caller=caller,
            category=category,
            active_only=active_only,
            opened_after=opened_after,
            extra_query=extra_query,
            order_by=order_by,
            limit=limit,
            offset=offset,
        )

    @server.tool(
        name="get_incident",
        description=(
            "Fetch one incident by number (e.g. INC0010023), including the "
            "description and resolution fields. Set include_journal to add the "
            "comments and work-notes history, which can be long."
        ),
        annotations=_read_only_annotations("Get incident"),
    )
    async def get_incident(
        number: str, include_journal: bool = False
    ) -> dict[str, Any]:
        """Fetch a single incident.

        Args:
            number: The incident number, e.g. "INC0010023".
            include_journal: Include comments and work_notes history.
        """
        return await service.get_incident(
            number=number, include_journal=include_journal
        )

    @server.tool(
        name="list_assignment_groups",
        description=(
            "List assignment groups, optionally filtered by a name substring. "
            "Use this to find the exact group name before assigning work."
        ),
        annotations=_read_only_annotations("List assignment groups"),
    )
    async def list_assignment_groups(
        name_contains: str | None = None,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List assignment groups.

        Args:
            name_contains: Case-insensitive substring of the group name.
            active_only: Exclude retired groups.
            limit: Records wanted, capped server-side.
            offset: Starting record offset for pagination.
        """
        return await service.list_assignment_groups(
            name_contains=name_contains,
            active_only=active_only,
            limit=limit,
            offset=offset,
        )

    @server.tool(
        name="lookup_ci_owner",
        description=(
            "Look up who owns or supports a configuration item in the CMDB, by "
            "CI name or sys_id. Read-only in every configuration. Falls back to "
            "partial name matches, flagged as unconfirmed."
        ),
        annotations=_read_only_annotations("Look up CI owner"),
    )
    async def lookup_ci_owner(identifier: str) -> dict[str, Any]:
        """Find the support and ownership contacts for a CI.

        Args:
            identifier: The CI's name (e.g. "app-prod-04") or its sys_id.
        """
        return await service.lookup_ci_owner(identifier=identifier)

    if not settings.read_only:
        _register_write_tools(server, service)

    return server


def _register_write_tools(server: MCPServer, service: ServiceNowService) -> None:
    """Register the mutating tools. Called only when writes are enabled."""

    @server.tool(
        name="create_incident",
        description=(
            "Open a new incident. Pass a stable correlation_id derived from the "
            "triggering event: if an incident already carries it, that incident "
            "is returned and nothing is created, which makes retries safe."
        ),
        annotations=ToolAnnotations(
            title="Create incident",
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=True,
        ),
    )
    async def create_incident(
        short_description: str,
        description: str | None = None,
        caller: str | None = None,
        assignment_group: str | None = None,
        category: str | None = None,
        urgency: int | None = None,
        impact: int | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Create an incident.

        Args:
            short_description: One-line summary. Required.
            description: Longer free-text detail.
            caller: sys_id of the caller record.
            assignment_group: Group name or sys_id to route to.
            category: Incident category, e.g. "network".
            urgency: 1-5, where 1 is most urgent.
            impact: 1-5, where 1 is broadest impact.
            correlation_id: Stable external key for idempotent retries.
        """
        return await service.create_incident(
            short_description=short_description,
            description=description,
            caller=caller,
            assignment_group=assignment_group,
            category=category,
            urgency=urgency,
            impact=impact,
            correlation_id=correlation_id,
        )

    @server.tool(
        name="update_incident",
        description=(
            "Update or annotate an existing incident by number. work_note is "
            "internal; comment is visible to the requester. At least one "
            "changed field is required."
        ),
        annotations=ToolAnnotations(
            title="Update incident",
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=False,
            open_world_hint=True,
        ),
    )
    async def update_incident(
        number: str,
        work_note: str | None = None,
        comment: str | None = None,
        state: str | None = None,
        assignment_group: str | None = None,
        priority: int | None = None,
        close_code: str | None = None,
        close_notes: str | None = None,
    ) -> dict[str, Any]:
        """Update an incident.

        Args:
            number: Incident number, e.g. "INC0010023".
            work_note: Internal note appended to the work-notes journal.
            comment: Customer-visible comment appended to the comments journal.
            state: New state label or number.
            assignment_group: Group name or sys_id to reassign to.
            priority: 1-5, where 1 is most severe.
            close_code: Resolution code, required by most instances to close.
            close_notes: Resolution narrative.
        """
        return await service.update_incident(
            number=number,
            work_note=work_note,
            comment=comment,
            state=state,
            assignment_group=assignment_group,
            priority=priority,
            close_code=close_code,
            close_notes=close_notes,
        )
