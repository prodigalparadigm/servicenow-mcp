"""Auth selection: basic vs OAuth2 client credentials, caching, and refresh."""

from __future__ import annotations

import asyncio
import base64

import httpx
import pytest

from servicenow_mcp.auth import (
    BasicAuthProvider,
    OAuth2ClientCredentialsProvider,
    build_auth_provider,
)
from servicenow_mcp.client import ServiceNowClient
from servicenow_mcp.config import AuthMode, Settings
from servicenow_mcp.errors import AuthenticationError, ConfigurationError
from servicenow_mcp.projection import INCIDENT_SUMMARY_FIELDS

from .conftest import BASE_URL, PASSWORD, USERNAME, build_transport, make_settings
from .fake_servicenow import FakeServiceNow, make_incidents


def oauth_settings(**overrides):
    values = {
        "auth_mode": AuthMode.OAUTH2_CLIENT_CREDENTIALS,
        "username": None,
        "password": None,
        "client_id": "client-abc",
        "client_secret": "client-secret",
    }
    values.update(overrides)
    return make_settings(**values)


# -- selection ----------------------------------------------------------


def test_basic_mode_selects_the_basic_provider():
    client = httpx.AsyncClient()
    provider = build_auth_provider(make_settings(), client)
    assert isinstance(provider, BasicAuthProvider)
    assert provider.mode == "basic"


def test_oauth_mode_selects_the_oauth_provider():
    client = httpx.AsyncClient()
    provider = build_auth_provider(oauth_settings(), client)
    assert isinstance(provider, OAuth2ClientCredentialsProvider)
    assert provider.mode == "oauth2_client_credentials"


def test_basic_mode_requires_a_username_and_password():
    with pytest.raises(ConfigurationError, match="SERVICENOW_USERNAME"):
        make_settings(password=None)


def test_oauth_mode_requires_a_client_id_and_secret():
    with pytest.raises(ConfigurationError, match="SERVICENOW_CLIENT_ID"):
        oauth_settings(client_secret=None)


def test_unknown_auth_mode_is_rejected():
    with pytest.raises(ConfigurationError, match="must be one of"):
        Settings.from_env(
            {
                "SERVICENOW_INSTANCE_URL": BASE_URL,
                "SERVICENOW_AUTH_MODE": "kerberos",
            }
        )


def test_default_oauth_token_url_is_derived_from_the_instance():
    assert oauth_settings().resolved_oauth_token_url == f"{BASE_URL}/oauth_token.do"
    assert (
        oauth_settings(
            oauth_token_url="https://sso.example/token"
        ).resolved_oauth_token_url
        == "https://sso.example/token"
    )


# -- basic auth on the wire --------------------------------------------


async def test_basic_auth_sends_the_expected_header(fake, sleeper):
    settings = make_settings()
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    header = fake.table_requests[0].headers["authorization"]
    assert header.startswith("Basic ")
    assert base64.b64decode(header[6:]).decode() == f"{USERNAME}:{PASSWORD}"
    assert fake.token_requests == []


async def test_wrong_basic_credentials_raise_and_are_not_retried(fake, sleeper):
    settings = make_settings(password="wrong-password")
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    with pytest.raises(AuthenticationError, match="rejected the credentials"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    # Static credentials: no point re-sending the same rejected header.
    assert len(fake.table_requests) == 1


# -- oauth on the wire --------------------------------------------------


async def test_oauth_fetches_a_token_then_sends_a_bearer_header(fake, sleeper):
    settings = oauth_settings()
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert len(fake.token_requests) == 1
    assert fake.token_requests[0]["grant_type"] == "client_credentials"
    assert fake.token_requests[0]["client_id"] == "client-abc"
    assert fake.table_requests[0].headers["authorization"] == "Bearer fake-access-token"


async def test_oauth_token_is_cached_across_calls(fake, sleeper):
    settings = oauth_settings()
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    for _ in range(4):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert len(fake.token_requests) == 1
    assert len(fake.table_requests) == 4


async def test_oauth_token_is_refreshed_after_expiry(fake):
    """expires_in is honoured, minus the refresh margin."""
    fake.token_expires_in = 120  # margin is 60s, so the token is good for 60s
    settings = oauth_settings()

    now = {"t": 0.0}
    http = httpx.AsyncClient(transport=fake.transport(), timeout=5.0)
    provider = OAuth2ClientCredentialsProvider(
        token_url=settings.resolved_oauth_token_url,
        client_id="client-abc",
        client_secret="client-secret",
        http_client=http,
        clock=lambda: now["t"],
    )

    headers: dict[str, str] = {}
    await provider.apply(headers)
    await provider.apply(headers)
    assert provider.token_requests == 1

    now["t"] = 59.0
    await provider.apply(headers)
    assert provider.token_requests == 1

    now["t"] = 61.0
    await provider.apply(headers)
    assert provider.token_requests == 2


async def test_concurrent_first_use_fetches_exactly_one_token():
    """The refresh is single-flight.

    Ten tool calls landing at once on a cold provider must not each open a
    token request: ServiceNow rate-limits ``/oauth_token.do`` like any other
    endpoint, and a thundering herd there can lock the integration out of the
    instance entirely.

    The token endpoint here deliberately takes time to answer, so every
    coroutine is inside ``_token`` before the first one finishes. Without the
    lock this test sees ten token requests; it is not a tautology.
    """
    in_flight: list[float] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        in_flight.append(asyncio.get_running_loop().time())
        await asyncio.sleep(0.05)
        return httpx.Response(
            200, json={"access_token": "fake-access-token", "expires_in": 1800}
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)
    provider = OAuth2ClientCredentialsProvider(
        token_url=f"{BASE_URL}/oauth_token.do",
        client_id="client-abc",
        client_secret="client-secret",
        http_client=http,
    )

    async def _one_call() -> str:
        headers: dict[str, str] = {}
        await provider.apply(headers)
        return headers["Authorization"]

    headers = await asyncio.gather(*(_one_call() for _ in range(10)))

    assert len(in_flight) == 1
    assert provider.token_requests == 1
    assert set(headers) == {"Bearer fake-access-token"}


async def test_invalidate_forces_exactly_one_refetch(fake):
    http = httpx.AsyncClient(transport=fake.transport(), timeout=5.0)
    provider = OAuth2ClientCredentialsProvider(
        token_url=f"{BASE_URL}/oauth_token.do",
        client_id="client-abc",
        client_secret="client-secret",
        http_client=http,
    )
    headers: dict[str, str] = {}
    await provider.apply(headers)
    assert provider.token_requests == 1

    assert await provider.invalidate() is True
    await provider.apply(headers)
    assert provider.token_requests == 2


def test_basic_auth_reports_that_reauthentication_is_pointless():
    """A static credential must not burn a retry replaying the same header."""
    provider = BasicAuthProvider("u", "p")
    assert asyncio.run(provider.invalidate()) is False


async def test_missing_expires_in_still_yields_a_usable_token(fake):
    fake.token_expires_in = None
    http = httpx.AsyncClient(transport=fake.transport(), timeout=5.0)
    provider = OAuth2ClientCredentialsProvider(
        token_url=f"{BASE_URL}/oauth_token.do",
        client_id="client-abc",
        client_secret="client-secret",
        http_client=http,
    )
    headers: dict[str, str] = {}
    await provider.apply(headers)
    assert headers["Authorization"] == "Bearer fake-access-token"


async def test_a_401_triggers_exactly_one_reauthentication(fake, sleeper):
    """An expired bearer token is refreshed once and the request replayed."""
    fake.rejected_tokens = {"fake-access-token"}
    settings = oauth_settings()
    transport = build_transport(fake, settings, sleep=sleeper)
    client = ServiceNowClient(settings, transport)

    # Make the second token fetch return a token the instance accepts.
    original_handle = fake._handle_token

    def rotate(request):
        response = original_handle(request)
        fake.access_token = "rotated-token"
        fake.rejected_tokens = set()
        return response

    fake._handle_token = rotate  # type: ignore[method-assign]

    page = await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert len(page.records) == 1
    assert transport.stats.reauth_attempts == 1
    assert len(fake.token_requests) == 2
    assert fake.table_requests[-1].headers["authorization"] == "Bearer rotated-token"


async def test_persistent_401_gives_up_after_one_reauth(fake, sleeper):
    fake.rejected_tokens = {"fake-access-token"}
    settings = oauth_settings()
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    with pytest.raises(AuthenticationError, match="rejected the credentials"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert len(fake.table_requests) == 2  # original + one replay, then stop


async def test_bad_client_secret_raises_authentication_error(fake, sleeper):
    settings = oauth_settings(client_secret="wrong")
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    with pytest.raises(AuthenticationError, match="HTTP 401"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


async def test_token_endpoint_errors_do_not_echo_the_secret(fake, sleeper):
    settings = oauth_settings(client_secret="super-secret-value")
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    with pytest.raises(AuthenticationError) as excinfo:
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)

    assert "super-secret-value" not in str(excinfo.value)


async def test_non_json_token_response_is_reported_clearly(sleeper):
    fake = FakeServiceNow(
        tables={"incident": make_incidents(1)},
        client_id="client-abc",
        client_secret="client-secret",
    )
    fake.fail_next(
        1,
        status=200,
        body="<html>SSO portal</html>",
        content_type="text/html",
        path_contains="oauth_token",
    )
    settings = oauth_settings()
    client = ServiceNowClient(settings, build_transport(fake, settings, sleep=sleeper))

    with pytest.raises(AuthenticationError, match="non-JSON"):
        await client.query_table("incident", fields=INCIDENT_SUMMARY_FIELDS, limit=1)


# -- config surface -----------------------------------------------------


async def test_audit_records_the_auth_mode(make_service, audit_stream):
    import json

    service = make_service()
    await service.search_incidents(limit=1)

    line = json.loads(audit_stream.getvalue().strip().splitlines()[-1])
    assert line["auth_mode"] == "basic"


def test_from_env_reads_both_modes():
    basic = Settings.from_env(
        {
            "SERVICENOW_INSTANCE_URL": f"{BASE_URL}/",
            "SERVICENOW_USERNAME": "u",
            "SERVICENOW_PASSWORD": "p",
        }
    )
    assert basic.auth_mode is AuthMode.BASIC
    assert basic.instance_url == BASE_URL  # trailing slash stripped

    oauth = Settings.from_env(
        {
            "SERVICENOW_INSTANCE_URL": BASE_URL,
            "SERVICENOW_AUTH_MODE": "oauth2_client_credentials",
            "SERVICENOW_CLIENT_ID": "cid",
            "SERVICENOW_CLIENT_SECRET": "csecret",
            "SERVICENOW_READ_ONLY": "false",
        }
    )
    assert oauth.auth_mode is AuthMode.OAUTH2_CLIENT_CREDENTIALS
    assert oauth.read_only is False


def test_plaintext_http_to_a_remote_host_is_refused():
    with pytest.raises(ConfigurationError, match="plaintext HTTP"):
        Settings.from_env(
            {
                "SERVICENOW_INSTANCE_URL": "http://prod.service-now.com",
                "SERVICENOW_USERNAME": "u",
                "SERVICENOW_PASSWORD": "p",
            }
        )


def test_plaintext_http_to_localhost_is_allowed_for_local_mocks():
    settings = Settings.from_env(
        {
            "SERVICENOW_INSTANCE_URL": "http://localhost:8080",
            "SERVICENOW_USERNAME": "u",
            "SERVICENOW_PASSWORD": "p",
        }
    )
    assert settings.instance_url == "http://localhost:8080"
