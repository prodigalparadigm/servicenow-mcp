"""429/5xx retry behaviour: backoff, jitter bounds, Retry-After, write safety."""

from __future__ import annotations

import random

import httpx
import pytest

from servicenow_mcp.client import ServiceNowClient
from servicenow_mcp.errors import (
    RateLimitedError,
    ServiceNowAPIError,
    TransportError,
)
from servicenow_mcp.projection import INCIDENT_SUMMARY_FIELDS
from servicenow_mcp.transport import RetryPolicy, TokenBucket

from .conftest import RecordingSleep, build_transport, make_settings
from .fake_servicenow import FakeServiceNow


def _client(fake: FakeServiceNow, sleeper: RecordingSleep, **overrides):
    settings = make_settings(**overrides)
    return ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))


async def test_429_is_retried_and_then_succeeds(fake, sleeper):
    fake.fail_next(2, status=429, retry_after="1")
    client = _client(fake, sleeper, max_retries=3)

    page = await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=5)

    assert len(page.records) == 5
    assert client.transport.stats.rate_limit_hits == 2
    assert client.transport.stats.retries == 2
    assert sleeper.calls == [1.0, 1.0]


async def test_retry_after_is_honoured_over_computed_backoff(fake, sleeper):
    fake.fail_next(1, status=429, retry_after="7")
    client = _client(fake, sleeper, max_retries=2, retry_base_delay=0.5)

    await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert sleeper.calls == [7.0]


async def test_retry_after_is_clamped(fake, sleeper):
    """A gateway advertising an hour must not park the server for an hour."""
    fake.fail_next(1, status=429, retry_after="3600")
    client = _client(fake, sleeper, max_retries=2, max_retry_after=30.0)

    await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert sleeper.calls == [30.0]


async def test_retry_after_accepts_an_http_date(fake, sleeper):
    fake.fail_next(1, status=429, retry_after="Sat, 22 Aug 2026 12:00:00 GMT")
    client = _client(fake, sleeper, max_retries=2, max_retry_after=60.0)

    await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    # The date is in the past relative to test-run time, so it clamps to 0 --
    # the important part is that it parsed rather than raising.
    assert len(sleeper.calls) == 1
    assert 0.0 <= sleeper.calls[0] <= 60.0


async def test_unparseable_retry_after_falls_back_to_backoff(fake, sleeper):
    fake.fail_next(1, status=429, retry_after="soon-ish")
    client = _client(fake, sleeper, max_retries=2, retry_base_delay=0.5)

    await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert len(sleeper.calls) == 1
    assert 0.0 <= sleeper.calls[0] <= 0.5


async def test_exhausted_budget_raises_rate_limited(fake, sleeper):
    fake.fail_next(10, status=429, retry_after="2")
    client = _client(fake, sleeper, max_retries=2)

    with pytest.raises(RateLimitedError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert excinfo.value.retry_after == 2.0
    # Initial attempt plus max_retries.
    assert len(fake.table_requests) == 3


async def test_503_is_retried_for_reads(fake, sleeper):
    fake.fail_next(1, status=503)
    client = _client(fake, sleeper, max_retries=2)

    page = await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=2)

    assert len(page.records) == 2
    assert client.transport.stats.retries == 1


async def test_400_is_not_retried(fake, sleeper):
    fake.fail_next(1, status=400, body='{"error":{"message":"Bad query","detail":"x"}}')
    client = _client(fake, sleeper, max_retries=3)

    with pytest.raises(ServiceNowAPIError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert excinfo.value.status_code == 400
    assert "Bad query" in str(excinfo.value)
    assert len(fake.table_requests) == 1
    assert sleeper.calls == []


async def test_timeouts_are_retried_for_reads(fake, sleeper):
    fake.fail_next(2, exception=httpx.ReadTimeout("timed out"))
    client = _client(fake, sleeper, max_retries=3)

    page = await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert len(page.records) == 1
    assert len(sleeper.calls) == 2


async def test_read_timeout_gives_up_after_the_budget(fake, sleeper):
    fake.fail_next(9, exception=httpx.ReadTimeout("timed out"))
    client = _client(fake, sleeper, max_retries=2)

    with pytest.raises(TransportError, match="after 3 attempt"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_write_is_not_replayed_after_a_timeout(fake, sleeper):
    """A POST that timed out may have been applied; replaying could duplicate."""
    fake.fail_next(1, exception=httpx.ReadTimeout("timed out"))
    client = _client(fake, sleeper, max_retries=3, read_only=False)

    with pytest.raises(TransportError, match="could duplicate a write"):
        await client.create_record(
            "incident", {"short_description": "x"}, fields=INCIDENT_SUMMARY_FIELDS
        )

    assert sleeper.calls == []
    assert len(fake.rows("incident")) == 25


async def test_write_is_replayed_after_a_connect_error(fake, sleeper):
    """A ConnectError means no bytes were sent, so replay is safe."""
    fake.fail_next(1, exception=httpx.ConnectError("no route"))
    client = _client(fake, sleeper, max_retries=3, read_only=False)

    record = await client.create_record(
        "incident",
        {"short_description": "created after a connect error"},
        fields=INCIDENT_SUMMARY_FIELDS,
    )

    assert record["short_description"] == "created after a connect error"
    assert len(fake.rows("incident")) == 26


async def test_write_is_retried_on_429(fake, sleeper):
    """429 proves the request was rejected, not applied, so it is safe."""
    fake.fail_next(1, status=429, retry_after="2")
    client = _client(fake, sleeper, max_retries=3, read_only=False)

    record = await client.create_record(
        "incident",
        {"short_description": "throttled then created"},
        fields=INCIDENT_SUMMARY_FIELDS,
    )

    assert record["short_description"] == "throttled then created"
    assert sleeper.calls == [2.0]
    assert len(fake.rows("incident")) == 26


async def test_write_is_not_retried_on_500(fake, sleeper):
    """A 500 may mean 'applied, then the response was lost'."""
    fake.fail_next(1, status=500)
    client = _client(fake, sleeper, max_retries=3, read_only=False)

    with pytest.raises(ServiceNowAPIError):
        await client.create_record(
            "incident", {"short_description": "x"}, fields=INCIDENT_SUMMARY_FIELDS
        )

    assert len(fake.table_requests) == 1


def test_backoff_grows_and_stays_within_bounds():
    policy = RetryPolicy(max_retries=6, base_delay=0.5, max_delay=8.0)
    rng = random.Random(7)

    for attempt in range(1, 7):
        ceiling = min(0.5 * 2 ** (attempt - 1), 8.0)
        samples = [policy.backoff(attempt, rng=rng) for _ in range(200)]
        assert all(0.0 <= s <= ceiling for s in samples)
        # Full jitter: the mean sits near half the ceiling, and the spread is
        # what actually decorrelates a fleet of retrying clients.
        assert 0.3 * ceiling <= sum(samples) / len(samples) <= 0.7 * ceiling


def test_backoff_ceiling_is_capped():
    policy = RetryPolicy(base_delay=1.0, max_delay=4.0)
    rng = random.Random(1)
    assert all(policy.backoff(20, rng=rng) <= 4.0 for _ in range(100))


def test_retry_after_clamping_rejects_negatives():
    policy = RetryPolicy(max_retry_after=30.0)
    assert policy.clamp_retry_after(-5.0) == 0.0
    assert policy.clamp_retry_after(100.0) == 30.0
    assert policy.clamp_retry_after(12.5) == 12.5


async def test_token_bucket_throttles_and_refills():
    clock = {"t": 0.0}
    slept: list[float] = []

    async def sleep(delay: float) -> None:
        slept.append(delay)
        clock["t"] += delay

    bucket = TokenBucket(60, clock=lambda: clock["t"], sleep=sleep)
    for _ in range(60):
        await bucket.acquire()
    assert slept == []

    await bucket.acquire()
    assert len(slept) == 1
    assert slept[0] == pytest.approx(1.0)


async def test_token_bucket_disabled_at_zero():
    async def sleep(_: float) -> None:  # pragma: no cover - must not run
        raise AssertionError("throttle should be disabled")

    bucket = TokenBucket(0, sleep=sleep)
    for _ in range(1_000):
        await bucket.acquire()
    assert bucket.waits == 0


async def test_retries_are_counted_per_tool_call_in_the_audit(
    make_service, fake, audit_stream
):
    import json

    fake.fail_next(2, status=429, retry_after="0")
    service = make_service(max_retries=3)

    await service.search_incidents(limit=2)

    line = json.loads(audit_stream.getvalue().strip().splitlines()[-1])
    assert line["http_retries"] == 2
    assert line["rate_limit_hits"] == 2
    assert line["http_requests"] == 3
