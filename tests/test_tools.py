"""End-to-end through the real MCP server: list_tools and call_tool."""

from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

EXPECTED_READ_TOOLS = [
    "server_info",
    "search_incidents",
    "get_incident",
    "list_assignment_groups",
    "lookup_ci_owner",
]


def payload(result) -> dict:
    """Decode a CallToolResult into the dict the tool returned."""
    if result.structured_content is not None:
        return result.structured_content
    assert result.content, "tool returned no content"
    return json.loads(result.content[0].text)


async def test_every_tool_is_advertised_with_a_schema_and_description(make_app):
    app = make_app(read_only=False)
    tools = await app.server.list_tools()

    names = [t.name for t in tools]
    assert set(EXPECTED_READ_TOOLS) <= set(names)
    assert {"create_incident", "update_incident"} <= set(names)

    for tool in tools:
        assert tool.description and len(tool.description) > 40, tool.name
        assert tool.input_schema["type"] == "object"


async def test_search_incidents_schema_exposes_the_filter_parameters(make_app):
    app = make_app()
    tool = next(t for t in await app.server.list_tools() if t.name == "search_incidents")

    properties = tool.input_schema["properties"]
    for name in ("text", "state", "priority", "assignment_group", "limit", "offset"):
        assert name in properties, name
    # Everything is optional: an agent can call it with no arguments.
    assert not tool.input_schema.get("required")


async def test_call_search_incidents(make_app):
    app = make_app()
    result = await app.server.call_tool(
        "search_incidents", {"assignment_group": "Network Support", "limit": 3}
    )

    assert result.is_error is False
    body = payload(result)
    assert body["count"] == 3
    assert body["has_more"] is True
    assert all(i["assignment_group"] == "Network Support" for i in body["incidents"])


async def test_call_search_incidents_with_no_arguments(make_app):
    app = make_app()
    body = payload(await app.server.call_tool("search_incidents", {}))
    assert body["count"] == 25


async def test_call_get_incident(make_app):
    app = make_app()
    body = payload(await app.server.call_tool("get_incident", {"number": "INC0000007"}))

    assert body["incident"]["number"] == "INC0000007"
    assert "description" in body["incident"]


async def test_call_get_incident_with_journal(make_app, fake):
    app = make_app()
    fake.rows("incident")[0]["work_notes"] = "Restarted the tunnel."
    body = payload(
        await app.server.call_tool(
            "get_incident", {"number": "INC0000001", "include_journal": True}
        )
    )
    assert body["incident"]["work_notes"] == "Restarted the tunnel."


async def test_call_list_assignment_groups(make_app):
    app = make_app()
    body = payload(
        await app.server.call_tool("list_assignment_groups", {"name_contains": "Ops"})
    )

    assert body["count"] == 1
    assert body["groups"][0]["name"] == "Database Ops"


async def test_call_lookup_ci_owner_exact(make_app):
    app = make_app()
    body = payload(
        await app.server.call_tool("lookup_ci_owner", {"identifier": "app-prod-04"})
    )

    assert body["exact_match"] is True
    assert body["owners"]["support_group"] == "Network Support"


async def test_call_lookup_ci_owner_by_sys_id(make_app):
    app = make_app()
    body = payload(
        await app.server.call_tool("lookup_ci_owner", {"identifier": "ci-app-prod-05"})
    )
    assert body["ci"]["name"] == "app-prod-05"


async def test_lookup_ci_owner_falls_back_to_flagged_partial_matches(make_app):
    app = make_app()
    body = payload(
        await app.server.call_tool("lookup_ci_owner", {"identifier": "app-prod"})
    )

    assert body["exact_match"] is False
    assert {c["name"] for c in body["candidates"]} == {"app-prod-04", "app-prod-05"}
    assert "Confirm which one" in body["note"]


async def test_call_server_info(make_app):
    app = make_app()
    body = payload(await app.server.call_tool("server_info", {}))

    assert body["read_only"] is True
    assert body["max_records_per_call"] == 500
    assert body["auth_mode"] == "basic"


async def test_calling_a_mutating_tool_in_read_only_mode_is_a_tool_error(make_app):
    app = make_app(read_only=True)

    with pytest.raises(ToolError, match="Unknown tool|read-only"):
        await app.server.call_tool(
            "create_incident", {"short_description": "should not exist"}
        )


async def test_call_create_incident(make_app, fake):
    app = make_app(read_only=False)
    body = payload(
        await app.server.call_tool(
            "create_incident",
            {
                "short_description": "Core switch unreachable",
                "assignment_group": "Network Support",
                "urgency": 1,
                "impact": 1,
            },
        )
    )

    assert body["created"] is True
    assert body["incident"]["short_description"] == "Core switch unreachable"
    assert body["incident"]["assignment_group"] == "Network Support"
    assert len(fake.rows("incident")) == 26


async def test_create_incident_is_idempotent_on_correlation_id(make_app, fake):
    app = make_app(read_only=False)
    args = {
        "short_description": "Disk pressure on app-prod-04",
        "correlation_id": "alert-9f31c2",
    }

    first = payload(await app.server.call_tool("create_incident", args))
    second = payload(await app.server.call_tool("create_incident", args))

    assert first["created"] is True
    assert second["created"] is False
    assert "already exists" in second["note"]
    assert second["incident"]["number"] == first["incident"]["number"]
    assert len(fake.rows("incident")) == 26


async def test_call_update_incident_appends_a_work_note(make_app, fake):
    app = make_app(read_only=False)
    body = payload(
        await app.server.call_tool(
            "update_incident",
            {
                "number": "INC0000003",
                "work_note": "Paged the on-call engineer.",
                "state": "in progress",
            },
        )
    )

    assert body["updated_fields"] == ["state", "work_notes"]
    assert body["incident"]["state"] == "In Progress"
    row = next(r for r in fake.rows("incident") if r["number"] == "INC0000003")
    assert "Paged the on-call engineer." in str(row["work_notes"])


async def test_update_incident_keeps_work_notes_and_comments_separate(make_app, fake):
    app = make_app(read_only=False)
    await app.server.call_tool(
        "update_incident",
        {
            "number": "INC0000004",
            "work_note": "internal detail",
            "comment": "customer visible",
        },
    )

    row = next(r for r in fake.rows("incident") if r["number"] == "INC0000004")
    assert row["work_notes"] == "internal detail"
    assert row["comments"] == "customer visible"


async def test_update_incident_with_nothing_to_change_is_rejected(make_app):
    app = make_app(read_only=False)

    with pytest.raises(ToolError, match="at least one field"):
        await app.server.call_tool("update_incident", {"number": "INC0000001"})


async def test_update_incident_rejects_an_unknown_number_before_writing(make_app, fake):
    app = make_app(read_only=False)

    with pytest.raises(ToolError, match="No incident numbered"):
        await app.server.call_tool(
            "update_incident", {"number": "INC9999999", "work_note": "x"}
        )

    assert not any(r.method in ("PATCH", "PUT") for r in fake.table_requests)


async def test_assignment_group_typo_is_surfaced_not_silently_dropped(make_app, fake):
    app = make_app(read_only=False)

    with pytest.raises(ToolError, match="No assignment group named"):
        await app.server.call_tool(
            "create_incident",
            {"short_description": "x", "assignment_group": "Netwrok Support"},
        )

    assert len(fake.rows("incident")) == 25


async def test_state_filter_accepts_labels_and_numbers(make_app):
    app = make_app()

    by_label = payload(
        await app.server.call_tool("search_incidents", {"state": "resolved", "limit": 50})
    )
    by_number = payload(
        await app.server.call_tool("search_incidents", {"state": "6", "limit": 50})
    )

    assert by_label["count"] == by_number["count"] > 0
    assert all(i["state"] == "Resolved" for i in by_label["incidents"])


async def test_unknown_state_label_is_a_helpful_error(make_app):
    app = make_app()

    with pytest.raises(ToolError, match="Unknown incident state"):
        await app.server.call_tool("search_incidents", {"state": "wibbling"})


async def test_priority_out_of_range_is_rejected(make_app):
    app = make_app()

    with pytest.raises(ToolError, match="between 1 and 5"):
        await app.server.call_tool("search_incidents", {"priority": 9})


async def test_unsortable_field_is_rejected_with_the_allowed_list(make_app):
    app = make_app()

    with pytest.raises(ToolError, match="Sortable fields"):
        await app.server.call_tool("search_incidents", {"order_by": "sys_created_by"})


async def test_query_injection_through_a_filter_value_is_refused(make_app, fake):
    """A '^' in a filter value would silently rewrite the query. Refuse it."""
    app = make_app()

    with pytest.raises(ToolError, match="may not contain"):
        await app.server.call_tool(
            "search_incidents", {"text": "vpn^active=false^ORDERBYnumber"}
        )

    assert fake.table_requests == []


async def test_extra_query_is_the_documented_escape_hatch(make_app, fake):
    app = make_app()
    body = payload(
        await app.server.call_tool(
            "search_incidents", {"extra_query": "category=network^priority=3", "limit": 50}
        )
    )

    assert body["count"] > 0
    sent = fake.table_requests[0].param("sysparm_query")
    assert "category=network^priority=3" in sent


async def test_active_only_filter(make_app):
    app = make_app()
    body = payload(
        await app.server.call_tool("search_incidents", {"active_only": True, "limit": 50})
    )
    assert 0 < body["count"] < 25


async def test_text_filter_matches_short_description(make_app):
    app = make_app()
    hit = payload(await app.server.call_tool("search_incidents", {"text": "VPN", "limit": 50}))
    miss = payload(await app.server.call_tool("search_incidents", {"text": "zzz"}))

    assert hit["count"] == 25
    assert miss["count"] == 0
