"""Credential providers: HTTP basic and OAuth2 client credentials.

Both providers implement :class:`AuthProvider`, so the transport layer never
branches on auth mode. The OAuth provider owns token lifetime: it refreshes
ahead of expiry, serialises concurrent refreshes behind a lock, and can be
told to invalidate a token when the instance answers 401.
"""

from __future__ import annotations

import asyncio
import base64
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, MutableMapping
from typing import Final

import httpx

from .config import AuthMode, Settings
from .errors import AuthenticationError

__all__ = [
    "AuthProvider",
    "BasicAuthProvider",
    "OAuth2ClientCredentialsProvider",
    "build_auth_provider",
]

#: Refresh this many seconds before the server-stated expiry. Covers clock skew
#: between us and the instance plus the flight time of the next request.
_REFRESH_MARGIN_SECONDS: Final[float] = 60.0

#: Fallback lifetime when the token endpoint omits ``expires_in``.
_DEFAULT_TOKEN_LIFETIME_SECONDS: Final[float] = 1500.0


class AuthProvider(ABC):
    """Applies credentials to outgoing requests."""

    #: Human-readable mode name, recorded in audit lines.
    mode: str = "unknown"

    @abstractmethod
    async def apply(self, headers: MutableMapping[str, str]) -> None:
        """Mutate ``headers`` in place to carry credentials."""

    async def invalidate(self) -> bool:
        """Discard any cached credential after a 401.

        Returns:
            True if a subsequent retry could plausibly succeed (i.e. a fresh
            credential can be obtained), False if the credential is static and
            retrying would just replay the same rejected header.
        """
        return False

    async def aclose(self) -> None:  # noqa: B027 - concrete no-op default
        """Release provider-owned resources.

        Deliberately concrete rather than abstract: most providers hold no
        resources, and forcing every one to write an empty override adds
        noise without adding safety.
        """


class BasicAuthProvider(AuthProvider):
    """RFC 7617 basic auth.

    The header is computed once. A 401 here means the username or password is
    wrong, so :meth:`invalidate` reports that retrying is pointless.
    """

    mode = AuthMode.BASIC.value

    def __init__(self, username: str, password: str) -> None:
        if not username or not password:
            raise AuthenticationError("Basic auth requires a username and password")
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        self._header = f"Basic {token}"

    async def apply(self, headers: MutableMapping[str, str]) -> None:
        headers["Authorization"] = self._header


class OAuth2ClientCredentialsProvider(AuthProvider):
    """OAuth2 ``client_credentials`` against ``/oauth_token.do``.

    ServiceNow's token endpoint is a form-encoded POST that returns
    ``access_token`` and ``expires_in``. Tokens are cached until
    ``expires_in`` minus :data:`_REFRESH_MARGIN_SECONDS`.
    """

    mode = AuthMode.OAUTH2_CLIENT_CREDENTIALS.value

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.AsyncClient,
        scope: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        timeout: float = 30.0,
    ) -> None:
        if not client_id or not client_secret:
            raise AuthenticationError(
                "OAuth2 client credentials require a client id and secret"
            )
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._http = http_client
        self._clock = clock
        self._timeout = timeout

        self._access_token: str | None = None
        self._expires_at: float = 0.0
        #: Created lazily so the provider can be constructed off the event loop:
        #: ``build_application`` runs synchronously, before any loop exists.
        self._lock: asyncio.Lock | None = None
        self.token_requests = 0

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def apply(self, headers: MutableMapping[str, str]) -> None:
        headers["Authorization"] = f"Bearer {await self._token()}"

    async def invalidate(self) -> bool:
        """Drop the cached token so the next call re-authenticates."""
        async with self._get_lock():
            self._access_token = None
            self._expires_at = 0.0
        return True

    async def _token(self) -> str:
        # Fast path outside the lock: the common case is a warm, valid token.
        if self._access_token is not None and self._clock() < self._expires_at:
            return self._access_token

        async with self._get_lock():
            # Re-check: another coroutine may have refreshed while we waited.
            if self._access_token is not None and self._clock() < self._expires_at:
                return self._access_token
            return await self._fetch_token()

    async def _fetch_token(self) -> str:
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            data["scope"] = self._scope

        self.token_requests += 1
        try:
            response = await self._http.post(
                self._token_url,
                data=data,
                headers={"Accept": "application/json"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise AuthenticationError(
                f"Could not reach the OAuth token endpoint: {exc}"
            ) from exc

        if response.status_code >= 400:
            # Deliberately does not echo the response body: token endpoints
            # sometimes reflect the client_secret back in error details.
            raise AuthenticationError(
                f"OAuth token request failed with HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthenticationError(
                "OAuth token endpoint returned a non-JSON body"
            ) from exc

        if not isinstance(payload, dict):
            raise AuthenticationError("OAuth token endpoint returned a non-object body")

        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise AuthenticationError("OAuth token response contained no access_token")

        lifetime = _coerce_lifetime(payload.get("expires_in"))
        self._access_token = token
        self._expires_at = self._clock() + max(lifetime - _REFRESH_MARGIN_SECONDS, 1.0)
        return token


def _coerce_lifetime(raw: object) -> float:
    """Interpret ``expires_in``, which instances return as int or string."""
    if isinstance(raw, bool):
        return _DEFAULT_TOKEN_LIFETIME_SECONDS
    if isinstance(raw, (int, float)) and raw > 0:
        return float(raw)
    if isinstance(raw, str):
        try:
            value = float(raw)
        except ValueError:
            return _DEFAULT_TOKEN_LIFETIME_SECONDS
        if value > 0:
            return value
    return _DEFAULT_TOKEN_LIFETIME_SECONDS


def build_auth_provider(
    settings: Settings,
    http_client: httpx.AsyncClient,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> AuthProvider:
    """Select the provider named by ``settings.auth_mode``."""
    if settings.auth_mode is AuthMode.BASIC:
        return BasicAuthProvider(
            username=settings.username or "", password=settings.password or ""
        )
    if settings.auth_mode is AuthMode.OAUTH2_CLIENT_CREDENTIALS:
        return OAuth2ClientCredentialsProvider(
            token_url=settings.resolved_oauth_token_url,
            client_id=settings.client_id or "",
            client_secret=settings.client_secret or "",
            scope=settings.oauth_scope,
            http_client=http_client,
            clock=clock,
            timeout=settings.timeout_seconds,
        )
    raise AuthenticationError(  # pragma: no cover - enum is exhaustive
        f"Unsupported auth mode {settings.auth_mode!r}"
    )
