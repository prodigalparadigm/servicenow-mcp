"""Configuration loading and validation.

All behaviour that a deployer needs to control -- credentials, safety caps,
retry budget, audit destination -- is resolved once at startup into a frozen
:class:`Settings` object. Nothing downstream reads ``os.environ``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import urlparse

from .errors import ConfigurationError

__all__ = ["ABSOLUTE_MAX_RECORDS", "ABSOLUTE_MAX_RETRIES", "AuthMode", "Settings"]

_LOCAL_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})
_TRUE: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_FALSE: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})

#: Absolute ceiling on ``SERVICENOW_MAX_RECORDS``. Even a deployer who sets the
#: cap to a silly number cannot make a single tool call return more than this;
#: the point of the cap is to bound model context, not just network traffic.
ABSOLUTE_MAX_RECORDS: Final[int] = 5_000

#: Absolute ceiling on ``SERVICENOW_MAX_RETRIES``. An MCP client is waiting
#: synchronously on every tool call, so a retry budget large enough to outlast
#: the client's own timeout buys nothing and looks like a hang.
ABSOLUTE_MAX_RETRIES: Final[int] = 10


class AuthMode(StrEnum):
    """Supported credential styles."""

    BASIC = "basic"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"


def _get(env: Mapping[str, str], key: str) -> str | None:
    value = env.get(key)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _get_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = _get(env, key)
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ConfigurationError(
        f"{key} must be one of {sorted(_TRUE | _FALSE)}; got {raw!r}"
    )


def _get_int(
    env: Mapping[str, str], key: str, default: int, *, minimum: int = 0
) -> int:
    raw = _get(env, key)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be an integer; got {raw!r}") from exc
    if value < minimum:
        raise ConfigurationError(f"{key} must be >= {minimum}; got {value}")
    return value


def _get_float(
    env: Mapping[str, str], key: str, default: float, *, minimum: float = 0.0
) -> float:
    raw = _get(env, key)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be a number; got {raw!r}") from exc
    if value < minimum:
        raise ConfigurationError(f"{key} must be >= {minimum}; got {value}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable, validated runtime configuration."""

    instance_url: str
    auth_mode: AuthMode = AuthMode.BASIC

    username: str | None = None
    password: str | None = None

    client_id: str | None = None
    client_secret: str | None = None
    oauth_token_url: str | None = None
    oauth_scope: str | None = None

    read_only: bool = True

    max_records: int = 500
    page_size: int = 50
    max_page_size: int = 100

    timeout_seconds: float = 30.0
    max_retries: int = 4
    retry_base_delay: float = 0.5
    retry_max_delay: float = 20.0
    max_retry_after: float = 60.0
    rate_limit_per_minute: int = 180

    audit_log_path: str | None = None
    actor: str = "mcp-client"

    def __post_init__(self) -> None:
        self._validate_instance_url()
        self._validate_credentials()
        self._validate_limits()

    # -- validation -----------------------------------------------------

    def _validate_instance_url(self) -> None:
        parsed = urlparse(self.instance_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError(
                "SERVICENOW_INSTANCE_URL must be an absolute http(s) URL, "
                f"got {self.instance_url!r}"
            )
        if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HOSTS:
            raise ConfigurationError(
                "Refusing plaintext HTTP to a non-local host; ServiceNow "
                "credentials would cross the network in the clear. Use https."
            )

    def _validate_credentials(self) -> None:
        if self.auth_mode is AuthMode.BASIC:
            if not (self.username and self.password):
                raise ConfigurationError(
                    "SERVICENOW_AUTH_MODE=basic requires SERVICENOW_USERNAME "
                    "and SERVICENOW_PASSWORD"
                )
        elif self.auth_mode is AuthMode.OAUTH2_CLIENT_CREDENTIALS:
            if not (self.client_id and self.client_secret):
                raise ConfigurationError(
                    "SERVICENOW_AUTH_MODE=oauth2_client_credentials requires "
                    "SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET"
                )
        else:  # pragma: no cover - enum is exhaustive
            raise ConfigurationError(f"Unsupported auth mode {self.auth_mode!r}")

    def _validate_limits(self) -> None:
        if self.max_records < 1:
            raise ConfigurationError("SERVICENOW_MAX_RECORDS must be >= 1")
        if self.max_records > ABSOLUTE_MAX_RECORDS:
            raise ConfigurationError(
                f"SERVICENOW_MAX_RECORDS may not exceed {ABSOLUTE_MAX_RECORDS}"
            )
        if self.page_size < 1:
            raise ConfigurationError("SERVICENOW_PAGE_SIZE must be >= 1")
        if self.max_page_size < 1:
            raise ConfigurationError("SERVICENOW_MAX_PAGE_SIZE must be >= 1")
        if self.page_size > self.max_page_size:
            raise ConfigurationError(
                "SERVICENOW_PAGE_SIZE may not exceed SERVICENOW_MAX_PAGE_SIZE"
            )
        if self.timeout_seconds <= 0:
            raise ConfigurationError("SERVICENOW_TIMEOUT_SECONDS must be > 0")
        if self.max_retries > ABSOLUTE_MAX_RETRIES:
            raise ConfigurationError(
                f"SERVICENOW_MAX_RETRIES may not exceed {ABSOLUTE_MAX_RETRIES}"
            )
        if self.retry_max_delay < self.retry_base_delay:
            raise ConfigurationError(
                "SERVICENOW_RETRY_MAX_DELAY may not be below "
                "SERVICENOW_RETRY_BASE_DELAY; the ceiling would clamp every "
                "backoff to the same value and defeat the jitter."
            )

    # -- derived --------------------------------------------------------

    @property
    def table_api_root(self) -> str:
        """Base URL of the Table API, without a trailing slash."""
        return f"{self.instance_url}/api/now/table"

    @property
    def resolved_oauth_token_url(self) -> str:
        """Token endpoint, defaulting to the instance's standard path."""
        return self.oauth_token_url or f"{self.instance_url}/oauth_token.do"

    def effective_page_size(self) -> int:
        """Page size actually used, clamped to both configured ceilings."""
        return min(self.page_size, self.max_page_size, self.max_records)

    # -- construction ---------------------------------------------------

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Build settings from a mapping, defaulting to the process env.

        Raises:
            ConfigurationError: if a required value is missing or a value is
                malformed. Failing here is deliberate: a half-configured MCP
                server that starts and then errors on every call is worse than
                one that refuses to start.
        """
        env = os.environ if env is None else env

        instance_url = _get(env, "SERVICENOW_INSTANCE_URL")
        if not instance_url:
            raise ConfigurationError("SERVICENOW_INSTANCE_URL is required")

        raw_mode = (_get(env, "SERVICENOW_AUTH_MODE") or AuthMode.BASIC.value).lower()
        try:
            auth_mode = AuthMode(raw_mode)
        except ValueError as exc:
            supported = ", ".join(m.value for m in AuthMode)
            raise ConfigurationError(
                f"SERVICENOW_AUTH_MODE must be one of: {supported}; got {raw_mode!r}"
            ) from exc

        return cls(
            instance_url=instance_url.rstrip("/"),
            auth_mode=auth_mode,
            username=_get(env, "SERVICENOW_USERNAME"),
            password=_get(env, "SERVICENOW_PASSWORD"),
            client_id=_get(env, "SERVICENOW_CLIENT_ID"),
            client_secret=_get(env, "SERVICENOW_CLIENT_SECRET"),
            oauth_token_url=_get(env, "SERVICENOW_OAUTH_TOKEN_URL"),
            oauth_scope=_get(env, "SERVICENOW_OAUTH_SCOPE"),
            read_only=_get_bool(env, "SERVICENOW_READ_ONLY", True),
            max_records=_get_int(env, "SERVICENOW_MAX_RECORDS", 500, minimum=1),
            page_size=_get_int(env, "SERVICENOW_PAGE_SIZE", 50, minimum=1),
            max_page_size=_get_int(env, "SERVICENOW_MAX_PAGE_SIZE", 100, minimum=1),
            timeout_seconds=_get_float(
                env, "SERVICENOW_TIMEOUT_SECONDS", 30.0, minimum=0.001
            ),
            max_retries=_get_int(env, "SERVICENOW_MAX_RETRIES", 4),
            retry_base_delay=_get_float(env, "SERVICENOW_RETRY_BASE_DELAY", 0.5),
            retry_max_delay=_get_float(env, "SERVICENOW_RETRY_MAX_DELAY", 20.0),
            max_retry_after=_get_float(env, "SERVICENOW_MAX_RETRY_AFTER", 60.0),
            rate_limit_per_minute=_get_int(
                env, "SERVICENOW_RATE_LIMIT_PER_MINUTE", 180
            ),
            audit_log_path=_get(env, "SERVICENOW_AUDIT_LOG_PATH"),
            actor=_get(env, "SERVICENOW_ACTOR") or "mcp-client",
        )
