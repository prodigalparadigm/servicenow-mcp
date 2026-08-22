"""Read-only mode: enforced at the tool list AND at the service layer."""

from __future__ import annotations

import pytest

from servicenow_mcp.config import Settings
from servicenow_mcp.errors import ReadOnlyModeError

READ_TOOLS = {
    "server_info",
    "search_incidents",
    "get_incident",
    "list_assignment_groups",
    "lookup_ci_owner",
}
WRITE_TOOLS = {"create_incident", "update_incident"}


def test_read_only_is_the_default():
    settings = Settings(
        instance_url="https://example.service-now.com", username="u", password="p"
    )
    assert settings.read_only is True


async def test_mutating_tools_are_not_advertised_when_read_only(make_app):
    app = make_app(read_only=True)
    names = {t.name for t in await app.server.list_tools()}

    assert READ_TOOLS <= names
    assert not (WRITE_TOOLS & names)


async def test_mutating_tools_appear_when_writes_are_enabled(make_app):
    app = make_app(read_only=False)
    names = {t.name for t in await app.server.list_tools()}

    assert WRITE_TOOLS <= names
    assert READ_TOOLS <= names


async def test_service_refuses_create_even_if_called_directly(make_service, fake):
    """A client can call a tool name it was never shown; the service still refuses."""
    service = make_service(read_only=True)

    with pytest.raises(ReadOnlyModeError, match="read-only mode"):
        await service.create_incident(short_description="should never be created")

    assert len(fake.rows("incident")) == 25
    # Refused before any HTTP traffic was generated.
    assert fake.table_requests == []


async def test_service_refuses_update_even_if_called_directly(make_service, fake):
    service = make_service(read_only=True)

    with pytest.raises(ReadOnlyModeError, match="read-only mode"):
        await service.update_incident(number="INC0000001", work_note="nope")

    assert fake.table_requests == []


async def test_refusal_is_audited_as_an_error(make_service, audit_stream):
    import json

    service = make_service(read_only=True)
    with pytest.raises(ReadOnlyModeError):
        await service.create_incident(short_description="x")

    line = json.loads(audit_stream.getvalue().strip().splitlines()[-1])
    assert line["tool"] == "create_incident"
    assert line["outcome"] == "error"
    assert line["error_type"] == "ReadOnlyModeError"
    assert line["read_only"] is True


async def test_reads_still_work_in_read_only_mode(make_service):
    service = make_service(read_only=True)
    result = await service.search_incidents(limit=3)
    assert result["count"] == 3


async def test_writes_work_when_enabled(make_service, fake):
    service = make_service(read_only=False)
    result = await service.create_incident(
        short_description="Printer on fire", category="hardware"
    )

    assert result["created"] is True
    assert result["incident"]["short_description"] == "Printer on fire"
    assert len(fake.rows("incident")) == 26


async def test_server_info_reports_the_mode(make_service):
    read_only = await make_service(read_only=True).server_info()
    writable = await make_service(read_only=False).server_info()

    assert read_only["read_only"] is True
    assert read_only["mutating_tools_enabled"] is False
    assert writable["read_only"] is False
    assert writable["mutating_tools_enabled"] is True


async def test_read_tools_are_annotated_read_only(make_app):
    app = make_app(read_only=False)
    tools = {t.name: t for t in await app.server.list_tools()}

    for name in READ_TOOLS:
        assert tools[name].annotations is not None
        assert tools[name].annotations.read_only_hint is True
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False
