"""Malformed and hostile responses: proxies, SSO portals, wrong shapes."""

from __future__ import annotations

import pytest

from servicenow_mcp.client import ServiceNowClient
from servicenow_mcp.errors import (
    MalformedResponseError,
    RecordNotFoundError,
    ServiceNowAPIError,
)
from servicenow_mcp.projection import INCIDENT_SUMMARY_FIELDS

from .conftest import build_transport, make_settings


def _client(fake, sleeper, **overrides):
    settings = make_settings(**overrides)
    return ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))


async def test_html_body_on_a_200_is_named_as_a_proxy_problem(fake, sleeper):
    fake.fail_next(
        1,
        status=200,
        body="<html><body>Sign in to continue</body></html>",
        content_type="text/html",
    )
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    message = str(excinfo.value)
    assert "proxy or SSO portal" in message
    assert "text/html" in message


async def test_truncated_json_is_reported_not_swallowed(fake, sleeper):
    fake.fail_next(1, status=200, body='{"result": [{"number": "INC00')
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError, match="Expected JSON"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_missing_result_key_names_the_keys_that_were_present(fake, sleeper):
    fake.fail_next(1, status=200, body='{"records": [], "meta": {}}')
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert "no 'result' key" in str(excinfo.value)
    assert "meta, records" in str(excinfo.value)


async def test_result_as_an_object_where_a_list_belongs(fake, sleeper):
    fake.fail_next(1, status=200, body='{"result": {"number": "INC0000001"}}')
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError, match="got a single object"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_result_as_a_scalar(fake, sleeper):
    fake.fail_next(1, status=200, body='{"result": "ok"}')
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError, match="got str"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_non_object_records_inside_the_result_list(fake, sleeper):
    fake.fail_next(1, status=200, body='{"result": [{"number": "INC1"}, "oops"]}')
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError, match="Record 1 .* is a str"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_top_level_json_array_instead_of_an_envelope(fake, sleeper):
    fake.fail_next(1, status=200, body='[{"number": "INC0000001"}]')
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError, match="got list"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_empty_body_on_a_200(fake, sleeper):
    fake.fail_next(1, status=200, body="")
    client = _client(fake, sleeper)

    with pytest.raises(MalformedResponseError, match="empty body"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_error_envelope_on_a_200_is_treated_as_an_error(fake, sleeper):
    """Scripted REST endpoints really do return errors with a 200."""
    fake.fail_next(
        1,
        status=200,
        body='{"error": {"message": "ACL restricts access", "detail": "incident"},'
        ' "status": "failure"}',
    )
    client = _client(fake, sleeper)

    with pytest.raises(ServiceNowAPIError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert "ACL restricts access" in str(excinfo.value)
    assert excinfo.value.detail == "incident"


async def test_error_detail_is_length_capped(fake, sleeper):
    fake.fail_next(
        1,
        status=400,
        body='{"error": {"message": "bad", "detail": "%s"}}' % ("z" * 5_000),
    )
    client = _client(fake, sleeper)

    with pytest.raises(ServiceNowAPIError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert excinfo.value.detail is not None
    assert len(excinfo.value.detail) <= 500


async def test_non_json_error_body_still_produces_a_typed_error(fake, sleeper):
    fake.fail_next(1, status=502, body="<h1>502 Bad Gateway</h1>", content_type="text/html")
    client = _client(fake, sleeper, max_retries=0)

    with pytest.raises(ServiceNowAPIError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert excinfo.value.status_code == 502
    # The query string is stripped from the message so filters never hit a log.
    assert "sysparm_query" not in str(excinfo.value)


async def test_missing_record_produces_a_clear_domain_error(make_service):
    service = make_service()

    with pytest.raises(RecordNotFoundError, match="INC9999999"):
        await service.get_incident(number="INC9999999")


async def test_create_response_without_a_record_is_flagged_as_ambiguous(
    fake, sleeper
):
    """A write that returns no body may or may not have applied. Say so."""
    fake.fail_next(1, status=201, body='{"result": null}')
    client = _client(fake, sleeper, read_only=False)

    with pytest.raises(MalformedResponseError, match="may or may not have been applied"):
        await client.create_record(
            "incident", {"short_description": "x"}, fields=INCIDENT_SUMMARY_FIELDS
        )


async def test_a_malformed_response_is_audited_as_an_error(
    make_service, fake, audit_stream
):
    import json

    fake.fail_next(1, status=200, body="not json", content_type="text/plain")
    service = make_service(max_retries=0)

    with pytest.raises(MalformedResponseError):
        await service.search_incidents(limit=1)

    line = json.loads(audit_stream.getvalue().strip().splitlines()[-1])
    assert line["outcome"] == "error"
    assert line["error_type"] == "MalformedResponseError"


async def test_garbage_total_count_header_is_ignored(fake, sleeper):
    """A header we cannot parse must not break pagination."""
    import httpx

    original = fake._query

    def wrapped(table, params):
        response = original(table, params)
        return httpx.Response(
            response.status_code,
            content=response.content,
            headers={**dict(response.headers), "X-Total-Count": "many"},
        )

    fake._query = wrapped  # type: ignore[method-assign]
    client = _client(fake, sleeper)

    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=3
    )

    assert len(page.records) == 3
    assert page.total_available is None
    assert page.has_more is True
