"""Shared fixtures. The whole suite runs offline against the fake instance."""

from __future__ import annotations

import io
import random
from collections.abc import Awaitable, Callable
from datetime import UTC
from typing import Any

import httpx
import pytest

from servicenow_mcp.app import Application, build_application
from servicenow_mcp.audit import AuditLogger
from servicenow_mcp.auth import build_auth_provider
from servicenow_mcp.client import ServiceNowClient
from servicenow_mcp.config import AuthMode, Settings
from servicenow_mcp.service import ServiceNowService
from servicenow_mcp.transport import RetryPolicy, ServiceNowTransport, TokenBucket

from .fake_servicenow import FakeServiceNow, make_cis, make_groups, make_incidents

BASE_URL = "https://example.service-now.com"
USERNAME = "svc_mcp"
PASSWORD = "correct-horse"


class RecordingSleep:
    """Stands in for ``asyncio.sleep`` so retry tests take no wall time."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.calls.append(delay)


def make_settings(**overrides: Any) -> Settings:
    """Basic-auth settings pointed at the fake instance."""
    values: dict[str, Any] = {
        "instance_url": BASE_URL,
        "auth_mode": AuthMode.BASIC,
        "username": USERNAME,
        "password": PASSWORD,
        "read_only": True,
        "max_records": 500,
        "page_size": 50,
        "max_page_size": 100,
        "rate_limit_per_minute": 0,
        "max_retries": 3,
        "retry_base_delay": 0.5,
        "retry_max_delay": 20.0,
        "max_retry_after": 60.0,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def fake() -> FakeServiceNow:
    """A fake instance preloaded with incidents, groups, and CIs."""
    return FakeServiceNow(
        tables={
            "incident": make_incidents(25),
            "sys_user_group": make_groups(),
            "cmdb_ci": make_cis(),
        },
        base_url=BASE_URL,
        username=USERNAME,
        password=PASSWORD,
        client_id="client-abc",
        client_secret="client-secret",
    )


@pytest.fixture
def audit_stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def sleeper() -> RecordingSleep:
    return RecordingSleep()


def build_transport(
    fake: FakeServiceNow,
    settings: Settings,
    *,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    seed: int = 1234,
) -> ServiceNowTransport:
    """Wire a transport onto the fake with deterministic jitter."""
    http_client = httpx.AsyncClient(transport=fake.transport(), timeout=5.0)
    provider = build_auth_provider(settings, http_client)
    sleep_fn = sleep or _noop_sleep
    return ServiceNowTransport(
        settings,
        http_client=http_client,
        auth_provider=provider,
        retry_policy=RetryPolicy(
            max_retries=settings.max_retries,
            base_delay=settings.retry_base_delay,
            max_delay=settings.retry_max_delay,
            max_retry_after=settings.max_retry_after,
        ),
        bucket=TokenBucket(settings.rate_limit_per_minute, sleep=sleep_fn),
        sleep=sleep_fn,
        rng=random.Random(seed),
    )


async def _noop_sleep(_: float) -> None:
    return None


@pytest.fixture
def make_client(fake: FakeServiceNow, sleeper: RecordingSleep):
    """Factory returning a client wired to the fake."""

    def _make(**overrides: Any) -> ServiceNowClient:
        settings = make_settings(**overrides)
        return ServiceNowClient(
            settings, build_transport(fake, settings, sleep=sleeper)
        )

    return _make


@pytest.fixture
def make_service(
    fake: FakeServiceNow, audit_stream: io.StringIO, sleeper: RecordingSleep
):
    """Factory returning a fully wired service, with an in-memory audit sink."""

    def _make(**overrides: Any) -> ServiceNowService:
        settings = make_settings(**overrides)
        client = ServiceNowClient(
            settings, build_transport(fake, settings, sleep=sleeper)
        )
        audit = AuditLogger(audit_stream, actor="pytest", now=_fixed_now)
        return ServiceNowService(settings, client, audit)

    return _make


@pytest.fixture
def make_app(fake: FakeServiceNow, audit_stream: io.StringIO):
    """Factory returning the full application, MCP server included."""

    def _make(**overrides: Any) -> Application:
        settings = make_settings(**overrides)
        return build_application(
            settings,
            transport=fake.transport(),
            audit=AuditLogger(audit_stream, actor="pytest", now=_fixed_now),
        )

    return _make


def _fixed_now():
    from datetime import datetime

    return datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)
