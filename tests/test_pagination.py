"""Pagination boundaries against the fake instance's real offset/limit slicing."""

from __future__ import annotations

import pytest

from servicenow_mcp.errors import AuthenticationError, RecordNotFoundError
from servicenow_mcp.projection import INCIDENT_SUMMARY_FIELDS

from .fake_servicenow import FakeServiceNow, make_incidents


async def test_single_page_when_limit_fits(make_client):
    client = make_client(page_size=50)
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=10
    )

    assert len(page.records) == 10
    assert page.has_more is True
    assert page.next_offset == 10
    assert page.total_available == 25
    assert page.requests == 1


async def test_pages_until_limit_reached(make_client, fake: FakeServiceNow):
    client = make_client(page_size=10)
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=25
    )

    assert len(page.records) == 25
    assert page.has_more is False
    assert page.next_offset is None
    # 10 + 10 + 5: the third request asks for 6 (limit+1 probe) and gets 5.
    assert page.requests == 3
    offsets = [r.int_param("sysparm_offset") for r in fake.table_requests]
    assert offsets == [0, 10, 20]
    assert [r.int_param("sysparm_limit") for r in fake.table_requests] == [10, 10, 6]


async def test_exact_boundary_uses_total_count_instead_of_probe(make_client):
    """limit == total: X-Total-Count answers has_more without an extra request."""
    client = make_client(page_size=25)
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=25
    )

    assert len(page.records) == 25
    assert page.has_more is False
    assert page.requests == 1
    assert page.total_available == 25


async def test_exact_boundary_without_total_count_probes(sleeper):
    """Instances that omit X-Total-Count cost one extra single-record probe."""
    from servicenow_mcp.client import ServiceNowClient

    from .conftest import build_transport, make_settings

    fake = FakeServiceNow(
        tables={"incident": make_incidents(20)},
        username="svc_mcp",
        password="correct-horse",
        send_total_count=False,
    )
    settings = make_settings(page_size=10)
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=20
    )

    assert len(page.records) == 20
    assert page.has_more is False
    assert page.total_available is None
    assert page.requests == 3
    assert fake.table_requests[-1].int_param("sysparm_limit") == 1


async def test_offset_is_honoured(make_client):
    client = make_client(page_size=50)
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=5, offset=20
    )

    assert [r["number"] for r in page.records] == [
        "INC0000021",
        "INC0000022",
        "INC0000023",
        "INC0000024",
        "INC0000025",
    ]
    assert page.has_more is False
    assert page.offset == 20


async def test_offset_past_end_returns_empty_page(make_client):
    client = make_client()
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=10, offset=1_000
    )

    assert page.records == []
    assert page.has_more is False
    assert page.next_offset is None


async def test_zero_limit_makes_no_request(make_client, fake: FakeServiceNow):
    client = make_client()
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=0
    )

    assert page.records == []
    assert page.requests == 0
    assert fake.table_requests == []


async def test_empty_result_set(make_client):
    client = make_client()
    page = await client.query_table(
        "incident",
        encoded_query="category=nonexistent",
        fields=INCIDENT_SUMMARY_FIELDS,
        limit=10,
    )

    assert page.records == []
    assert page.has_more is False
    assert page.total_available == 0


@pytest.mark.parametrize("limit", [1, 7, 24, 25, 26])
async def test_service_envelope_is_consistent_across_limits(make_service, limit):
    service = make_service(page_size=10)
    result = await service.search_incidents(limit=limit, order_by="number")

    expected = min(limit, 25)
    assert result["count"] == expected
    assert len(result["incidents"]) == expected
    assert result["has_more"] is (expected < 25)
    assert result["next_offset"] == (expected if expected < 25 else None)
    assert result["total_matching"] == 25


async def test_paging_through_with_next_offset_covers_every_record(make_service):
    """Walking next_offset visits all 25 incidents exactly once."""
    service = make_service(page_size=4)
    seen: list[str] = []
    offset = 0
    for _ in range(20):  # bounded so a paging bug fails instead of hanging
        result = await service.search_incidents(limit=7, offset=offset, order_by="number")
        seen.extend(i["number"] for i in result["incidents"])
        if not result["has_more"]:
            break
        offset = result["next_offset"]

    assert len(seen) == 25
    assert len(set(seen)) == 25
    assert seen == sorted(seen)


# -- single-record fetch -------------------------------------------------


async def test_get_record_by_sys_id(make_client, fake: FakeServiceNow):
    client = make_client()
    record = await client.get_record(
        "incident", "inc-sys-0009", fields=INCIDENT_SUMMARY_FIELDS
    )

    assert record["number"] == "INC0000009"
    # Addressed by sys_id in the path, not as a filtered collection query.
    assert fake.table_requests[-1].path.endswith("/incident/inc-sys-0009")
    assert fake.table_requests[-1].param("sysparm_query") is None


async def test_get_record_turns_a_404_into_a_not_found_error(make_client):
    """A 404 on a record fetch is 'no such record', not a generic API failure."""
    client = make_client()

    with pytest.raises(RecordNotFoundError, match="no-such-sys-id"):
        await client.get_record(
            "incident", "no-such-sys-id", fields=INCIDENT_SUMMARY_FIELDS
        )


async def test_get_record_propagates_other_api_errors(make_client, fake: FakeServiceNow):
    """Only 404 is reinterpreted; a 403 must not be masked as 'not found'."""
    fake.fail_next(1, status=403)
    client = make_client()

    with pytest.raises(AuthenticationError):
        await client.get_record(
            "incident", "inc-sys-0001", fields=INCIDENT_SUMMARY_FIELDS
        )


async def test_get_record_on_an_empty_result_is_not_found(make_client, fake: FakeServiceNow):
    fake.fail_next(1, status=200, body='{"result": {}}')
    client = make_client()

    with pytest.raises(RecordNotFoundError):
        await client.get_record(
            "incident", "inc-sys-0001", fields=INCIDENT_SUMMARY_FIELDS
        )
