"""The hard record cap: an agent cannot pull the whole table by accident."""

from __future__ import annotations

import pytest

from servicenow_mcp.client import ServiceNowClient
from servicenow_mcp.config import (
    ABSOLUTE_MAX_RECORDS,
    ABSOLUTE_MAX_RETRIES,
    Settings,
)
from servicenow_mcp.errors import ConfigurationError
from servicenow_mcp.projection import INCIDENT_SUMMARY_FIELDS

from .conftest import build_transport, make_settings
from .fake_servicenow import FakeServiceNow, make_incidents


async def test_absurd_limit_is_clamped_to_max_records(
    make_client, fake: FakeServiceNow
):
    client = make_client(max_records=10, page_size=5)
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=50_000
    )

    assert len(page.records) == 10
    assert page.capped is True
    assert page.requested_limit == 50_000
    assert page.effective_limit == 10
    assert page.has_more is True
    # Crucially: a bounded number of round trips, not 50000/page_size.
    assert page.requests <= 3
    assert len(fake.table_requests) <= 3


async def test_cap_bounds_request_count_on_a_large_table(sleeper):
    fake = FakeServiceNow(
        tables={"incident": make_incidents(5_000)},
        username="svc_mcp",
        password="correct-horse",
    )
    settings = make_settings(max_records=100, page_size=25)
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=999_999
    )

    assert len(page.records) == 100
    assert page.capped is True
    # ceil(101 / 25) == 5 pages, and not one more.
    assert page.requests == 5


async def test_page_size_never_exceeds_the_cap(make_client, fake: FakeServiceNow):
    """A page_size larger than max_records must not over-fetch on the wire."""
    client = make_client(max_records=3, page_size=100, max_page_size=100)
    page = await client.query_table(
        "incident", fields=INCIDENT_SUMMARY_FIELDS, limit=100
    )

    assert len(page.records) == 3
    assert all((r.int_param("sysparm_limit") or 0) <= 4 for r in fake.table_requests), [
        r.int_param("sysparm_limit") for r in fake.table_requests
    ]


async def test_service_surfaces_the_cap_to_the_model(make_service):
    service = make_service(max_records=5, page_size=5)
    result = await service.search_incidents(limit=1_000)

    assert result["count"] == 5
    assert result["limit_capped"] is True
    assert "caps a single call at 5" in result["note"]
    assert result["has_more"] is True
    assert result["next_offset"] == 5


async def test_assignment_group_listing_is_capped_too(make_service):
    service = make_service(max_records=2, page_size=2)
    result = await service.list_assignment_groups(limit=100)

    assert result["count"] == 2
    assert result["limit_capped"] is True


def test_config_rejects_a_cap_above_the_absolute_ceiling():
    with pytest.raises(ConfigurationError, match="may not exceed"):
        make_settings(max_records=ABSOLUTE_MAX_RECORDS + 1)


def test_config_rejects_a_zero_cap():
    with pytest.raises(ConfigurationError, match="must be >= 1"):
        Settings(
            instance_url="https://example.service-now.com",
            username="u",
            password="p",
            max_records=0,
        )


def test_config_rejects_an_unbounded_retry_budget():
    """A budget outlasting the client's own timeout reads as a hang, not resilience."""
    with pytest.raises(ConfigurationError, match="MAX_RETRIES may not exceed"):
        make_settings(max_retries=ABSOLUTE_MAX_RETRIES + 1)


def test_config_rejects_a_backoff_ceiling_below_its_floor():
    with pytest.raises(ConfigurationError, match="RETRY_MAX_DELAY may not be below"):
        make_settings(retry_base_delay=10.0, retry_max_delay=1.0)


def test_config_rejects_a_page_size_above_its_own_ceiling():
    with pytest.raises(ConfigurationError, match="PAGE_SIZE may not exceed"):
        make_settings(page_size=200, max_page_size=100)
