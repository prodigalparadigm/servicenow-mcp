"""Structured audit logging: who, what, how much, how long -- and never stdout."""

from __future__ import annotations

import io
import json
import sys

import pytest

from servicenow_mcp.audit import AuditEvent, AuditLogger, redact
from servicenow_mcp.errors import ConfigurationError, RecordNotFoundError


def lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().strip().splitlines() if line]


async def test_every_tool_call_emits_exactly_one_record(make_service, audit_stream):
    service = make_service()

    await service.search_incidents(limit=3)
    await service.get_incident(number="INC0000002")
    await service.list_assignment_groups()
    await service.lookup_ci_owner(identifier="app-prod-04")
    await service.server_info()

    entries = lines(audit_stream)
    assert [e["tool"] for e in entries] == [
        "search_incidents",
        "get_incident",
        "list_assignment_groups",
        "lookup_ci_owner",
        "server_info",
    ]


async def test_record_carries_the_full_who_what_howmuch_howlong(
    make_service, audit_stream
):
    service = make_service()
    await service.search_incidents(assignment_group="Network Support", limit=4)

    entry = lines(audit_stream)[-1]
    assert entry["event"] == "mcp.tool_call"
    assert entry["actor"] == "pytest"
    assert entry["tool"] == "search_incidents"
    assert entry["arguments"]["assignment_group"] == "Network Support"
    assert entry["arguments"]["limit"] == 4
    assert entry["outcome"] == "ok"
    assert entry["result_records"] == 4
    assert entry["result_bytes"] > 0
    assert entry["http_requests"] == 1
    assert entry["duration_ms"] >= 0
    assert entry["read_only"] is True
    assert entry["auth_mode"] == "basic"
    assert entry["ts"].startswith("2026-08-22T12:00:00")


async def test_truncation_is_recorded(make_service, audit_stream):
    service = make_service(max_records=5)
    await service.search_incidents(limit=1_000)

    assert lines(audit_stream)[-1]["truncated"] is True


async def test_failures_are_recorded_with_type_and_message(make_service, audit_stream):
    service = make_service()

    with pytest.raises(RecordNotFoundError):
        await service.get_incident(number="INC0000000")

    entry = lines(audit_stream)[-1]
    assert entry["outcome"] == "error"
    assert entry["error_type"] == "RecordNotFoundError"
    assert "No incident numbered" in entry["error_message"]


async def test_write_calls_are_audited_with_their_arguments(make_service, audit_stream):
    service = make_service(read_only=False)
    await service.create_incident(short_description="Audit me", correlation_id="corr-1")

    entry = lines(audit_stream)[-1]
    assert entry["tool"] == "create_incident"
    assert entry["read_only"] is False
    assert entry["arguments"]["correlation_id"] == "corr-1"
    assert entry["result_records"] == 1


async def test_every_line_is_valid_standalone_json(make_service, audit_stream):
    service = make_service()
    for number in ("INC0000001", "INC0000002", "INC0000003"):
        await service.get_incident(number=number)

    raw = audit_stream.getvalue()
    assert raw.endswith("\n")
    for line in raw.strip().splitlines():
        assert json.loads(line)["event"] == "mcp.tool_call"


# -- redaction ----------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "client_secret",
        "api_key",
        "Authorization",
        "refresh_token",
        "PASSWD",
    ],
)
def test_credential_shaped_keys_are_redacted(key):
    assert redact({key: "hunter2"})[key] == "[redacted]"


def test_ordinary_keys_are_kept():
    assert redact({"number": "INC1", "limit": 5}) == {"number": "INC1", "limit": 5}


def test_long_values_are_capped_but_their_length_is_reported():
    result = redact({"description": "x" * 5_000})["description"]
    assert result.endswith("[5000 chars]")
    assert len(result) < 300


def test_large_collections_are_capped():
    result = redact({"items": list(range(100))})["items"]
    assert len(result) == 21
    assert result[-1] == "[80 more items]"


def test_deep_nesting_is_cut_off():
    deep: dict = {"a": {"b": {"c": {"d": {"e": "too far"}}}}}
    assert "[nested]" in json.dumps(redact(deep))


def test_nested_secrets_are_redacted_too():
    result = redact({"config": {"client_secret": "s3cret", "url": "https://x"}})
    assert result["config"]["client_secret"] == "[redacted]"
    assert result["config"]["url"] == "https://x"


def test_unserialisable_values_do_not_break_the_line():
    class Odd:
        pass

    event = AuditEvent(tool="t", actor="a", arguments=redact({"x": Odd()}))
    assert json.loads(event.to_json(timestamp="2026-08-22T12:00:00Z"))["arguments"] == {
        "x": "[Odd]"
    }


# -- the stdout rule ----------------------------------------------------


def test_audit_logger_refuses_stdout():
    """stdout carries the MCP stdio transport; writing there breaks the client."""
    with pytest.raises(ValueError, match="may not target stdout"):
        AuditLogger(sys.stdout)


def test_default_sink_is_stderr():
    logger = AuditLogger()
    assert logger._stream is sys.stderr


def test_from_path_writes_json_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger.from_path(str(path), actor="svc")
    logger.emit(AuditEvent(tool="search_incidents", actor="svc"))
    logger.emit(AuditEvent(tool="get_incident", actor="svc", outcome="error"))

    entries = [json.loads(line) for line in path.read_text().splitlines()]
    assert [e["tool"] for e in entries] == ["search_incidents", "get_incident"]
    assert entries[1]["outcome"] == "error"


def test_from_path_with_no_path_falls_back_to_stderr():
    assert AuditLogger.from_path(None)._stream is sys.stderr


class _Exploding(io.StringIO):
    """A sink that fails the way a full disk or a revoked permission does."""

    def write(self, _: str) -> int:  # type: ignore[override]
        raise OSError("No space left on device")


def test_a_broken_sink_is_counted_not_swallowed(capsys):
    logger = AuditLogger(_Exploding())

    logger.emit(AuditEvent(tool="t", actor="a"))
    logger.emit(AuditEvent(tool="t", actor="a"))

    # The failure is visible: counted, and reported to stderr exactly once so a
    # persistently broken sink cannot itself become the flood.
    assert logger.dropped_events == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("audit sink failed") == 1
    assert "No space left on device" in captured.err


async def test_a_broken_sink_never_breaks_a_tool_call(make_service):
    service = make_service()
    service._audit = AuditLogger(_Exploding())

    result = await service.search_incidents(limit=2)

    assert len(result["incidents"]) == 2
    assert service._audit.dropped_events == 1


def test_an_unopenable_audit_path_fails_at_startup(tmp_path):
    """Degrading silently to stderr would hide that the file is never written."""
    unwritable = tmp_path / "no-such-dir" / "audit.jsonl"

    with pytest.raises(ConfigurationError, match="could not be opened"):
        AuditLogger.from_path(str(unwritable))


async def test_nothing_is_written_to_stdout_during_a_tool_call(make_service, capsys):
    service = make_service()
    await service.search_incidents(limit=2)
    assert capsys.readouterr().out == ""
