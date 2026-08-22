"""Tool bodies, independent of the MCP protocol layer.

Each public method here is one MCP tool. Keeping them free of MCP types means
the whole surface is testable by calling Python functions, and that the server
module stays a thin registration shim over a stable SDK API.

Responsibilities that live at this layer:

* **Read-only enforcement.** ``server.py`` also omits mutating tools from the
  tool list when read-only is on, but a tool list is advisory -- a client can
  call a name it was never advertised. This layer refuses regardless.
* **Audit.** Every method is wrapped in exactly one audit record.
* **Projection.** Raw records never leave this layer unprojected.
* **Idempotency.** ``create_incident`` accepts a ``correlation_id`` and checks
  for an existing incident carrying it before writing.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, Final

from .audit import AuditEvent, AuditLogger
from .client import Page, ServiceNowClient
from .config import Settings
from .errors import ReadOnlyModeError, RecordNotFoundError
from .projection import (
    ASSIGNMENT_GROUP_FIELDS,
    CMDB_CI_FIELDS,
    INCIDENT_DETAIL_FIELDS,
    INCIDENT_SUMMARY_FIELDS,
    project_record,
    project_records,
)
from .query import QueryBuilder, QuerySyntaxError, sanitize_operand

__all__ = ["ServiceNowService", "INCIDENT_STATES"]

INCIDENT_TABLE: Final[str] = "incident"
GROUP_TABLE: Final[str] = "sys_user_group"
CMDB_TABLE: Final[str] = "cmdb_ci"

#: Out-of-the-box incident state codes. Filters accept either the number or the
#: label so a model does not have to know ServiceNow's integers; instances with
#: customised state models can always fall back to ``extra_query``.
INCIDENT_STATES: Final[Mapping[str, str]] = {
    "new": "1",
    "in progress": "2",
    "in_progress": "2",
    "active": "2",
    "on hold": "3",
    "on_hold": "3",
    "pending": "3",
    "resolved": "6",
    "closed": "7",
    "cancelled": "8",
    "canceled": "8",
}

#: Priority/urgency/impact all use 1..5 with 1 most severe.
_MIN_SEVERITY: Final[int] = 1
_MAX_SEVERITY: Final[int] = 5

#: Fields a caller may sort incidents by. An allowlist, because ORDERBY takes a
#: raw column name and an unbounded one invites both errors and probing.
_SORTABLE_INCIDENT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "number",
        "opened_at",
        "sys_updated_on",
        "priority",
        "urgency",
        "impact",
        "state",
        "short_description",
    }
)


def _normalize_state(value: str | int) -> str:
    """Map a state label or number to the numeric code stored on the record."""
    text = str(value).strip()
    if text.isdigit():
        return text
    code = INCIDENT_STATES.get(text.lower())
    if code is None:
        known = ", ".join(sorted({k for k in INCIDENT_STATES if " " in k or k.isalpha()}))
        raise QuerySyntaxError(
            f"Unknown incident state {value!r}. Use a number or one of: {known}. "
            "For a customised state model, pass extra_query instead."
        )
    return code


def _normalize_severity(name: str, value: int | str) -> str:
    try:
        number = int(str(value).strip())
    except ValueError as exc:
        raise QuerySyntaxError(f"{name} must be an integer 1-5, got {value!r}") from exc
    if not _MIN_SEVERITY <= number <= _MAX_SEVERITY:
        raise QuerySyntaxError(f"{name} must be between 1 and 5, got {number}")
    return str(number)


class ServiceNowService:
    """Implements every exposed tool."""

    def __init__(
        self,
        settings: Settings,
        client: ServiceNowClient,
        audit: AuditLogger,
    ) -> None:
        self._settings = settings
        self._client = client
        self._audit = audit

    @property
    def read_only(self) -> bool:
        return self._settings.read_only

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- infrastructure -------------------------------------------------

    @asynccontextmanager
    async def _record(
        self, tool: str, arguments: Mapping[str, Any]
    ) -> AsyncIterator[AuditEvent]:
        """Wrap a tool body in one audit record with HTTP cost attribution."""
        stats = self._client.transport.stats
        before_requests = stats.requests
        before_retries = stats.retries
        before_429 = stats.rate_limit_hits
        async with self._audit.tool_call(tool, arguments) as event:
            event.read_only = self._settings.read_only
            event.auth_mode = self._client.transport.auth_mode
            try:
                yield event
            finally:
                event.http_requests = stats.requests - before_requests
                event.http_retries = stats.retries - before_retries
                event.rate_limit_hits = stats.rate_limit_hits - before_429

    def _require_writable(self, tool: str) -> None:
        if self._settings.read_only:
            raise ReadOnlyModeError(
                f"'{tool}' is a mutating operation and this server is running in "
                "read-only mode. Set SERVICENOW_READ_ONLY=false to enable "
                "writes; this is a deployment decision, not something a client "
                "can override at call time."
            )

    @staticmethod
    def _measure(event: AuditEvent, payload: Any, *, records: int | None = None) -> None:
        """Record the size of what is about to be handed to the model."""
        event.result_records = records
        try:
            event.result_bytes = len(json.dumps(payload, default=str))
        except (TypeError, ValueError):  # pragma: no cover - defensive
            event.result_bytes = None

    @staticmethod
    def _page_envelope(page: Page, records: list[dict[str, Any]]) -> dict[str, Any]:
        """Uniform pagination envelope so the model can continue reliably."""
        envelope: dict[str, Any] = {
            "count": len(records),
            "offset": page.offset,
            "has_more": page.has_more,
            "next_offset": page.next_offset,
        }
        if page.total_available is not None:
            envelope["total_matching"] = page.total_available
        if page.capped:
            envelope["limit_capped"] = True
            envelope["note"] = (
                f"Requested {page.requested_limit} records; this server caps a "
                f"single call at {page.effective_limit}. Page through with "
                "next_offset rather than raising the limit."
            )
        return envelope

    # -- read tools -----------------------------------------------------

    async def search_incidents(
        self,
        *,
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
        """Search incidents with filters and pagination.

        Every filter is optional and AND-ed. Returns a summary projection --
        enough to triage and choose, not the full record. Call ``get_incident``
        for the narrative fields of a specific number.
        """
        args = {
            "text": text,
            "state": state,
            "priority": priority,
            "assignment_group": assignment_group,
            "assigned_to": assigned_to,
            "caller": caller,
            "category": category,
            "active_only": active_only,
            "opened_after": opened_after,
            "extra_query": extra_query,
            "order_by": order_by,
            "limit": limit,
            "offset": offset,
        }
        async with self._record("search_incidents", args) as event:
            builder = QueryBuilder()
            if text:
                # LIKE on short_description is the cheap, index-friendly search.
                # A true full-text search would use sysparm_query=123TEXTQUERY321,
                # which behaves differently per instance and is not portable.
                builder.where("short_description", "LIKE", text)
            if state is not None:
                builder.where("state", "=", _normalize_state(state))
            if priority is not None:
                builder.where("priority", "=", _normalize_severity("priority", priority))
            if assignment_group:
                builder.where("assignment_group.name", "=", assignment_group)
            if assigned_to:
                builder.where("assigned_to.user_name", "=", assigned_to)
            if caller:
                builder.where("caller_id.user_name", "=", caller)
            if category:
                builder.where("category", "=", category)
            if active_only is not None:
                builder.where("active", "=", active_only)
            if opened_after:
                builder.where("opened_at", ">", sanitize_operand(opened_after))
            builder.raw(extra_query)

            self._apply_incident_order(builder, order_by)

            page = await self._client.query_table(
                INCIDENT_TABLE,
                encoded_query=builder.render(),
                fields=INCIDENT_SUMMARY_FIELDS,
                limit=limit,
                offset=offset,
            )
            records = project_records(page.records, INCIDENT_SUMMARY_FIELDS)
            result = {"incidents": records, **self._page_envelope(page, records)}
            event.truncated = page.capped or page.has_more
            self._measure(event, result, records=len(records))
            return result

    @staticmethod
    def _apply_incident_order(builder: QueryBuilder, order_by: str) -> None:
        spec = (order_by or "").strip()
        if not spec:
            return
        field = spec[1:] if spec.startswith("-") else spec
        if field not in _SORTABLE_INCIDENT_FIELDS:
            raise QuerySyntaxError(
                f"Cannot sort incidents by {field!r}. Sortable fields: "
                + ", ".join(sorted(_SORTABLE_INCIDENT_FIELDS))
            )
        builder.order_by_spec(spec)

    async def get_incident(
        self, *, number: str, include_journal: bool = False
    ) -> dict[str, Any]:
        """Fetch one incident by its number (e.g. ``INC0010023``).

        ``include_journal`` adds the ``comments`` and ``work_notes`` journals,
        which are unbounded in length and are therefore off by default and
        truncated when on.
        """
        async with self._record(
            "get_incident", {"number": number, "include_journal": include_journal}
        ) as event:
            fields = list(INCIDENT_DETAIL_FIELDS)
            if not include_journal:
                fields = [f for f in fields if f not in ("comments", "work_notes")]

            record = await self._find_incident(number, fields)
            result = {"incident": project_record(record, fields)}
            self._measure(event, result, records=1)
            return result

    async def _find_incident(
        self, number: str, fields: Sequence[str]
    ) -> dict[str, Any]:
        """Resolve an incident by number, raising a clear error on a miss."""
        cleaned = sanitize_operand(number).strip()
        if not cleaned:
            raise QuerySyntaxError("An incident number is required.")
        query = QueryBuilder().where("number", "=", cleaned).render()
        record = await self._client.find_one(
            INCIDENT_TABLE, encoded_query=query, fields=fields
        )
        if record is None:
            raise RecordNotFoundError(
                f"No incident numbered {cleaned!r}. Numbers are case-sensitive "
                "and usually look like INC0010023."
            )
        return record

    async def list_assignment_groups(
        self,
        *,
        name_contains: str | None = None,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List ITSM assignment groups, for routing an incident correctly."""
        args = {
            "name_contains": name_contains,
            "active_only": active_only,
            "limit": limit,
            "offset": offset,
        }
        async with self._record("list_assignment_groups", args) as event:
            builder = QueryBuilder()
            if name_contains:
                builder.where("name", "LIKE", name_contains)
            if active_only:
                builder.where("active", "=", True)
            builder.order_by("name")

            page = await self._client.query_table(
                GROUP_TABLE,
                encoded_query=builder.render(),
                fields=ASSIGNMENT_GROUP_FIELDS,
                limit=limit,
                offset=offset,
            )
            records = project_records(page.records, ASSIGNMENT_GROUP_FIELDS)
            result = {"groups": records, **self._page_envelope(page, records)}
            event.truncated = page.capped or page.has_more
            self._measure(event, result, records=len(records))
            return result

    async def lookup_ci_owner(self, *, identifier: str) -> dict[str, Any]:
        """Answer "who owns this CI" from the CMDB. Always read-only.

        Accepts a CI name or a sys_id. Returns the ownership and support
        columns plus an explicit ``owners`` roll-up, so the model does not have
        to know which of ``support_group`` / ``managed_by`` / ``owned_by`` a
        given instance actually populates -- in practice it is rarely all three.
        """
        async with self._record("lookup_ci_owner", {"identifier": identifier}) as event:
            cleaned = sanitize_operand(identifier).strip()
            if not cleaned:
                raise QuerySyntaxError("A CI name or sys_id is required.")

            record = await self._client.find_one(
                CMDB_TABLE,
                encoded_query=QueryBuilder().where("sys_id", "=", cleaned).render(),
                fields=CMDB_CI_FIELDS,
            )
            if record is None:
                record = await self._client.find_one(
                    CMDB_TABLE,
                    encoded_query=QueryBuilder().where("name", "=", cleaned).render(),
                    fields=CMDB_CI_FIELDS,
                )
            if record is None:
                # Last resort: a fuzzy match, flagged as such so the model does
                # not silently act on the wrong host.
                page = await self._client.query_table(
                    CMDB_TABLE,
                    encoded_query=QueryBuilder()
                    .where("name", "LIKE", cleaned)
                    .order_by("name")
                    .render(),
                    fields=CMDB_CI_FIELDS,
                    limit=5,
                )
                if not page.records:
                    raise RecordNotFoundError(
                        f"No configuration item matching {cleaned!r}."
                    )
                candidates = project_records(page.records, CMDB_CI_FIELDS)
                result = {
                    "exact_match": False,
                    "candidates": candidates,
                    "note": (
                        "No exact name or sys_id match; these are partial name "
                        "matches. Confirm which one is meant before acting."
                    ),
                }
                self._measure(event, result, records=len(candidates))
                return result

            ci = project_record(record, CMDB_CI_FIELDS)
            result = {
                "exact_match": True,
                "ci": ci,
                "owners": {
                    key: ci[key]
                    for key in (
                        "support_group",
                        "assignment_group",
                        "managed_by",
                        "owned_by",
                        "assigned_to",
                    )
                    if ci.get(key)
                },
            }
            self._measure(event, result, records=1)
            return result

    async def server_info(self) -> dict[str, Any]:
        """Report the server's operating mode, caps, and available tools.

        Cheap for a client to call first: it tells the model whether writes are
        possible at all, so it does not plan an action the server will refuse.
        """
        async with self._record("server_info", {}) as event:
            result = {
                "instance_url": self._settings.instance_url,
                "read_only": self._settings.read_only,
                "auth_mode": self._settings.auth_mode.value,
                "max_records_per_call": self._settings.max_records,
                "page_size": self._settings.effective_page_size(),
                "mutating_tools_enabled": not self._settings.read_only,
                "returned_incident_fields": list(INCIDENT_SUMMARY_FIELDS),
            }
            self._measure(event, result)
            return result

    # -- write tools ----------------------------------------------------

    async def create_incident(
        self,
        *,
        short_description: str,
        description: str | None = None,
        caller: str | None = None,
        assignment_group: str | None = None,
        category: str | None = None,
        urgency: int | None = None,
        impact: int | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Create an incident. Refused unless the server is writable.

        Pass a stable ``correlation_id`` for idempotency: if an incident with
        that id already exists it is returned untouched instead of a duplicate
        being opened. Agent retries and client reconnects both replay tool
        calls, and a duplicate P1 is a real operational cost.
        """
        args = {
            "short_description": short_description,
            "description": description,
            "caller": caller,
            "assignment_group": assignment_group,
            "category": category,
            "urgency": urgency,
            "impact": impact,
            "correlation_id": correlation_id,
        }
        async with self._record("create_incident", args) as event:
            self._require_writable("create_incident")

            summary = (short_description or "").strip()
            if not summary:
                raise QuerySyntaxError("short_description is required and may not be empty.")

            if correlation_id:
                existing = await self._client.find_one(
                    INCIDENT_TABLE,
                    encoded_query=QueryBuilder()
                    .where("correlation_id", "=", correlation_id)
                    .render(),
                    fields=INCIDENT_DETAIL_FIELDS,
                )
                if existing is not None:
                    result = {
                        "incident": project_record(existing, INCIDENT_DETAIL_FIELDS),
                        "created": False,
                        "note": (
                            f"An incident with correlation_id {correlation_id!r} "
                            "already exists; returning it instead of creating a "
                            "duplicate."
                        ),
                    }
                    event.result_records = 1
                    self._measure(event, result, records=1)
                    return result

            payload: dict[str, Any] = {"short_description": summary}
            if description:
                payload["description"] = description
            if category:
                payload["category"] = category
            if urgency is not None:
                payload["urgency"] = _normalize_severity("urgency", urgency)
            if impact is not None:
                payload["impact"] = _normalize_severity("impact", impact)
            if correlation_id:
                payload["correlation_id"] = correlation_id
            if caller:
                payload["caller_id"] = caller
            if assignment_group:
                payload["assignment_group"] = await self._resolve_group_sys_id(
                    assignment_group
                )

            record = await self._client.create_record(
                INCIDENT_TABLE, payload, fields=INCIDENT_DETAIL_FIELDS
            )
            result = {
                "incident": project_record(record, INCIDENT_DETAIL_FIELDS),
                "created": True,
            }
            self._measure(event, result, records=1)
            return result

    async def update_incident(
        self,
        *,
        number: str,
        work_note: str | None = None,
        comment: str | None = None,
        state: str | None = None,
        assignment_group: str | None = None,
        priority: int | None = None,
        close_code: str | None = None,
        close_notes: str | None = None,
    ) -> dict[str, Any]:
        """Annotate or update an existing incident. Refused when read-only.

        ``work_note`` is internal; ``comment`` is customer-visible. They are
        separate parameters rather than one "note" because conflating them is
        how internal troubleshooting detail ends up emailed to a requester.
        """
        args = {
            "number": number,
            "work_note": work_note,
            "comment": comment,
            "state": state,
            "assignment_group": assignment_group,
            "priority": priority,
            "close_code": close_code,
            "close_notes": close_notes,
        }
        async with self._record("update_incident", args) as event:
            self._require_writable("update_incident")

            payload: dict[str, Any] = {}
            if work_note:
                payload["work_notes"] = work_note
            if comment:
                payload["comments"] = comment
            if state is not None:
                payload["state"] = _normalize_state(state)
            if priority is not None:
                payload["priority"] = _normalize_severity("priority", priority)
            if close_code:
                payload["close_code"] = close_code
            if close_notes:
                payload["close_notes"] = close_notes
            if assignment_group:
                payload["assignment_group"] = await self._resolve_group_sys_id(
                    assignment_group
                )

            if not payload:
                raise QuerySyntaxError(
                    "update_incident needs at least one field to change. Pass a "
                    "work_note, comment, state, priority, assignment_group, or "
                    "close details."
                )

            # Resolve the number to a sys_id first: PATCH addresses records by
            # sys_id, and this also fails fast on a bad number before writing.
            existing = await self._find_incident(number, ["sys_id", "number"])
            record = await self._client.update_record(
                INCIDENT_TABLE,
                str(existing["sys_id"]),
                payload,
                fields=INCIDENT_DETAIL_FIELDS,
            )
            result = {
                "incident": project_record(record, INCIDENT_DETAIL_FIELDS),
                "updated_fields": sorted(payload),
            }
            self._measure(event, result, records=1)
            return result

    async def _resolve_group_sys_id(self, group: str) -> str:
        """Accept a group name or sys_id and return a sys_id.

        Writing a display name into a reference field works on some instances
        and silently no-ops on others depending on how the dictionary entry is
        configured. Resolving explicitly makes the behaviour the same everywhere
        and surfaces a typo as an error instead of an unassigned incident.
        """
        cleaned = sanitize_operand(group).strip()
        if not cleaned:
            raise QuerySyntaxError("assignment_group may not be empty.")

        for field_name in ("sys_id", "name"):
            record = await self._client.find_one(
                GROUP_TABLE,
                encoded_query=QueryBuilder().where(field_name, "=", cleaned).render(),
                fields=["sys_id", "name"],
            )
            if record is not None and record.get("sys_id"):
                return str(record["sys_id"])

        raise RecordNotFoundError(
            f"No assignment group named {cleaned!r}. Use list_assignment_groups "
            "to find the exact name."
        )
