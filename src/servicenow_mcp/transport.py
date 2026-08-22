"""HTTP transport: throttling, retries, 429 handling, response validation.

Everything that makes a real ServiceNow integration annoying lives here so the
client and service layers can stay declarative:

* a client-side token bucket, because instances enforce per-user API limits and
  a rejected request still costs you a slot in the instance's counter;
* exponential backoff with full jitter, bounded by a configured ceiling;
* ``Retry-After`` is honoured -- as seconds or as an HTTP date -- but clamped,
  so a misconfigured gateway cannot park the server for an hour;
* mutating verbs are retried only on statuses that prove the request was *not*
  applied (429, 503). A POST that timed out may well have created an incident,
  and silently creating two is worse than surfacing the timeout.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import email.utils
import random
import time
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any, Final

import httpx

from .auth import AuthProvider
from .config import Settings
from .errors import (
    AuthenticationError,
    MalformedResponseError,
    RateLimitedError,
    ServiceNowAPIError,
    TransportError,
)

__all__ = ["RetryPolicy", "TokenBucket", "ServiceNowTransport"]

#: Statuses worth retrying for a read.
_RETRYABLE_READ_STATUSES: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})

#: Statuses worth retrying for a write. A 500 or a 504 may mean "applied, then
#: the response was lost", so writes are not retried on those.
_RETRYABLE_WRITE_STATUSES: Final[frozenset[int]] = frozenset({429, 503})

_IDEMPOTENT_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})

#: Truncation applied to error bodies before they reach a log or the model.
_ERROR_BODY_CHARS: Final[int] = 500


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded exponential backoff with full jitter."""

    max_retries: int = 4
    base_delay: float = 0.5
    max_delay: float = 20.0
    max_retry_after: float = 60.0

    def backoff(self, attempt: int, *, rng: random.Random) -> float:
        """Delay before retry number ``attempt`` (1-based).

        Full jitter -- ``uniform(0, base * 2**(attempt-1))`` -- rather than
        equal jitter, because a fleet of agents retrying in lockstep is exactly
        how a rate limit turns into an outage.
        """
        ceiling = min(self.base_delay * (2 ** max(attempt - 1, 0)), self.max_delay)
        return rng.uniform(0.0, ceiling)

    def clamp_retry_after(self, seconds: float) -> float:
        """Bound a server-advertised ``Retry-After``."""
        return max(0.0, min(seconds, self.max_retry_after))


class TokenBucket:
    """Async token bucket used as a client-side request throttle.

    ``rate_per_minute <= 0`` disables throttling entirely.
    """

    def __init__(
        self,
        rate_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._enabled = rate_per_minute > 0
        self._capacity = float(max(rate_per_minute, 1))
        self._rate_per_second = max(rate_per_minute, 0) / 60.0
        self._tokens = self._capacity
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock: asyncio.Lock | None = None
        self.waits = 0

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def acquire(self) -> None:
        """Consume one token, waiting if the bucket is empty."""
        if not self._enabled:
            return
        async with self._get_lock():
            while True:
                now = self._clock()
                elapsed = max(now - self._updated, 0.0)
                self._updated = now
                self._tokens = min(
                    self._capacity, self._tokens + elapsed * self._rate_per_second
                )
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                self.waits += 1
                await self._sleep(deficit / self._rate_per_second)


@dataclass(slots=True)
class TransportStats:
    """Counters surfaced in audit records."""

    requests: int = 0
    retries: int = 0
    rate_limit_hits: int = 0
    reauth_attempts: int = 0


class ServiceNowTransport:
    """Authenticated, throttled, retrying JSON transport for the Table API."""

    def __init__(
        self,
        settings: Settings,
        *,
        http_client: httpx.AsyncClient,
        auth_provider: AuthProvider,
        retry_policy: RetryPolicy | None = None,
        bucket: TokenBucket | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._settings = settings
        self._http = http_client
        self._auth = auth_provider
        self._policy = retry_policy or RetryPolicy(
            max_retries=settings.max_retries,
            base_delay=settings.retry_base_delay,
            max_delay=settings.retry_max_delay,
            max_retry_after=settings.max_retry_after,
        )
        self._bucket = bucket or TokenBucket(
            settings.rate_limit_per_minute, sleep=sleep
        )
        self._sleep = sleep
        self._rng = rng or random.Random()
        self.stats = TransportStats()

    @property
    def auth_mode(self) -> str:
        return self._auth.mode

    async def aclose(self) -> None:
        await self._auth.aclose()
        await self._http.aclose()

    # -- public API -----------------------------------------------------

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> tuple[Any, httpx.Headers]:
        """Perform a request and return ``(parsed_json, response_headers)``.

        Raises:
            AuthenticationError: credentials rejected after a re-auth attempt.
            RateLimitedError: 429 persisted past the retry budget.
            ServiceNowAPIError: a non-retryable 4xx/5xx or an error envelope.
            MalformedResponseError: 2xx body was not the documented shape.
            TransportError: network failure that outlived the retry budget.
        """
        response = await self._send_with_retries(
            method, url, params=params, json_body=json_body
        )
        return _parse_json_body(response), response.headers

    # -- retry loop -----------------------------------------------------

    async def _send_with_retries(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None,
        json_body: Mapping[str, Any] | None,
    ) -> httpx.Response:
        method = method.upper()
        idempotent = method in _IDEMPOTENT_METHODS
        retryable_statuses = (
            _RETRYABLE_READ_STATUSES if idempotent else _RETRYABLE_WRITE_STATUSES
        )
        reauth_used = False
        last_retry_after: float | None = None

        # ``attempt`` counts real delivery attempts. A 401 that triggers a
        # token refresh does not consume the budget -- it is a credential
        # problem, not a capacity problem -- but ``reauth_used`` bounds it to
        # a single extra round trip so a permanently rejecting instance cannot
        # spin here.
        attempt = 0
        while True:
            await self._bucket.acquire()
            headers: MutableMapping[str, str] = {
                "Accept": "application/json",
                "User-Agent": "servicenow-mcp/0.1",
            }
            await self._auth.apply(headers)

            self.stats.requests += 1
            try:
                response = await self._http.request(
                    method,
                    url,
                    params=dict(params) if params else None,
                    json=dict(json_body) if json_body is not None else None,
                    headers=headers,
                    timeout=self._settings.timeout_seconds,
                )
            except httpx.HTTPError as exc:
                # A ConnectError means no bytes reached the instance, so even a
                # write is safe to replay. A timeout or a mid-flight reset on a
                # write is not: the record may already exist.
                replayable = idempotent or isinstance(exc, httpx.ConnectError)
                if not replayable:
                    raise TransportError(
                        f"{method} {_safe_url(url)} failed and was not retried "
                        f"because replaying it could duplicate a write: {exc}"
                    ) from exc
                if attempt >= self._policy.max_retries:
                    raise TransportError(
                        f"{method} {_safe_url(url)} failed after "
                        f"{attempt + 1} attempt(s): {exc}"
                    ) from exc
                attempt += 1
                self.stats.retries += 1
                await self._pause(self._policy.backoff(attempt, rng=self._rng))
                continue

            status = response.status_code

            if status < 400:
                return response

            if status == 401 and not reauth_used and await self._auth.invalidate():
                # One shot at refreshing a credential; a static credential
                # reports that refreshing would change nothing.
                self.stats.reauth_attempts += 1
                reauth_used = True
                continue

            if status in (401, 403):
                raise AuthenticationError(
                    f"ServiceNow rejected the credentials for {method} "
                    f"{_safe_url(url)} (HTTP {status}). Check the account's "
                    "roles and ACLs for the target table."
                )

            if status == 429:
                self.stats.rate_limit_hits += 1
                last_retry_after = self._retry_after_seconds(response)

            if status in retryable_statuses and attempt < self._policy.max_retries:
                delay = (
                    last_retry_after
                    if (status == 429 and last_retry_after is not None)
                    else self._policy.backoff(attempt + 1, rng=self._rng)
                )
                attempt += 1
                self.stats.retries += 1
                await self._pause(delay)
                continue

            if status == 429:
                raise RateLimitedError(
                    f"ServiceNow rate limit not cleared after "
                    f"{attempt + 1} attempt(s) on {method} {_safe_url(url)}",
                    retry_after=last_retry_after,
                )

            raise _api_error(response, method, url)

    async def _pause(self, delay: float) -> None:
        # A zero delay is still awaited: it yields to the event loop, so a
        # tight retry loop cannot starve other work.
        await self._sleep(max(0.0, delay))

    def _retry_after_seconds(self, response: httpx.Response) -> float | None:
        """Parse ``Retry-After`` as delta-seconds or HTTP-date, then clamp.

        Returns None for a header we cannot interpret, so the caller falls back
        to computed backoff rather than failing on a malformed header.
        """
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        raw = raw.strip()
        try:
            return self._policy.clamp_retry_after(float(raw))
        except ValueError:
            pass
        try:
            parsed = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if parsed is None:  # pragma: no cover - older stdlib behaviour
            return None
        now = _dt.datetime.now(tz=parsed.tzinfo or _dt.UTC)
        return self._policy.clamp_retry_after((parsed - now).total_seconds())


# -- response handling --------------------------------------------------


def _parse_json_body(response: httpx.Response) -> Any:
    """Decode a 2xx body, tolerating the empty-body case.

    A successful response that is not JSON almost always means something sits
    between us and the instance: an SSO redirect, a WAF block page, a
    maintenance notice. That is a distinct failure from a ServiceNow error and
    is reported as one.
    """
    if response.status_code == 204 or not response.content:
        return None
    content_type = response.headers.get("Content-Type", "")
    try:
        payload = response.json()
    except ValueError as exc:
        snippet = response.text[:_ERROR_BODY_CHARS]
        raise MalformedResponseError(
            f"Expected JSON from ServiceNow but got Content-Type "
            f"{content_type or 'unknown'!r}. This usually means a proxy or SSO "
            f"portal answered instead of the instance. Body began: {snippet!r}"
        ) from exc

    # A 200 carrying an error envelope is a real ServiceNow behaviour on some
    # scripted REST paths, so it is checked even on success.
    if isinstance(payload, dict) and "error" in payload and "result" not in payload:
        raise _envelope_error(payload, response.status_code)
    return payload


def _envelope_error(payload: Mapping[str, Any], status: int) -> ServiceNowAPIError:
    error = payload.get("error")
    if isinstance(error, Mapping):
        message = str(error.get("message") or "ServiceNow returned an error")
        detail = error.get("detail")
        detail_str = str(detail)[:_ERROR_BODY_CHARS] if detail else None
    else:
        message = str(error)[:_ERROR_BODY_CHARS]
        detail_str = None
    return ServiceNowAPIError(message, status_code=status, detail=detail_str)


def _api_error(response: httpx.Response, method: str, url: str) -> ServiceNowAPIError:
    """Build the error for a terminal non-2xx response."""
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict) and "error" in payload:
        return _envelope_error(payload, response.status_code)
    return ServiceNowAPIError(
        f"{method} {_safe_url(url)} returned HTTP {response.status_code}",
        status_code=response.status_code,
        detail=response.text[:_ERROR_BODY_CHARS] or None,
    )


def _safe_url(url: str) -> str:
    """Strip the query string so credentials or PII never reach a log line."""
    return url.split("?", 1)[0]
