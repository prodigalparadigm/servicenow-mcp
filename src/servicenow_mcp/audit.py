"""Structured audit logging for every tool invocation.

One JSON object per line, one line per tool call, carrying: who called, which
tool, the (redacted) arguments, whether it succeeded, how much data came back,
how many HTTP round trips it took, and how long it ran.

Two constraints shape the implementation:

* **Never stdout.** Under the MCP stdio transport, stdout is the protocol
  channel. A single stray ``print`` corrupts the JSON-RPC stream and the client
  disconnects with an opaque parse error. The default sink is stderr and the
  file sink is opened explicitly.
* **Never the secret.** Arguments are model-supplied and may contain anything.
  Keys that look credential-bearing are redacted by name, and every value is
  length-capped, so the audit trail cannot itself become the leak.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import IO, Any, Final

__all__ = ["AuditEvent", "AuditLogger", "redact"]

#: Substring match, case-insensitive. Broad on purpose: a false positive costs
#: one unreadable audit value, a false negative costs a credential in a log.
_SENSITIVE_KEY_MARKERS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "authorization",
    "api_key",
    "apikey",
    "private",
)

_REDACTED: Final[str] = "[redacted]"
_MAX_VALUE_CHARS: Final[int] = 200
_MAX_ITEMS: Final[int] = 20


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def redact(value: Any, *, key: str | None = None, _depth: int = 0) -> Any:
    """Return a log-safe copy of ``value``.

    Redacts by key name, caps string length, caps collection size, and refuses
    to recurse more than a few levels into model-supplied structures.
    """
    if key is not None and _is_sensitive(key):
        return _REDACTED
    if _depth >= 4:
        return "[nested]"
    if isinstance(value, str):
        if len(value) > _MAX_VALUE_CHARS:
            return value[:_MAX_VALUE_CHARS] + f"...[{len(value)} chars]"
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for index, (k, v) in enumerate(value.items()):
            if index >= _MAX_ITEMS:
                out["..."] = f"[{len(value) - _MAX_ITEMS} more keys]"
                break
            out[str(k)] = redact(v, key=str(k), _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        capped = [redact(v, _depth=_depth + 1) for v in items[:_MAX_ITEMS]]
        if len(items) > _MAX_ITEMS:
            capped.append(f"[{len(items) - _MAX_ITEMS} more items]")
        return capped
    return f"[{type(value).__name__}]"


@dataclass(slots=True)
class AuditEvent:
    """Mutable record filled in over the life of one tool call."""

    tool: str
    actor: str
    arguments: dict[str, Any] = field(default_factory=dict)
    outcome: str = "ok"
    error_type: str | None = None
    error_message: str | None = None
    #: Records returned to the model, when the tool returns records.
    result_records: int | None = None
    #: Serialised size of the payload handed back, in bytes.
    result_bytes: int | None = None
    #: Whether the result was cut short by the record cap.
    truncated: bool | None = None
    #: HTTP round trips this call cost, including retries.
    http_requests: int = 0
    http_retries: int = 0
    rate_limit_hits: int = 0
    duration_ms: float = 0.0
    read_only: bool | None = None
    auth_mode: str | None = None

    def to_json(self, *, timestamp: str) -> str:
        payload = {
            "ts": timestamp,
            "event": "mcp.tool_call",
            "actor": self.actor,
            "tool": self.tool,
            "arguments": self.arguments,
            "outcome": self.outcome,
            "duration_ms": round(self.duration_ms, 2),
            "http_requests": self.http_requests,
            "http_retries": self.http_retries,
            "rate_limit_hits": self.rate_limit_hits,
        }
        if self.read_only is not None:
            payload["read_only"] = self.read_only
        if self.auth_mode is not None:
            payload["auth_mode"] = self.auth_mode
        if self.result_records is not None:
            payload["result_records"] = self.result_records
        if self.result_bytes is not None:
            payload["result_bytes"] = self.result_bytes
        if self.truncated is not None:
            payload["truncated"] = self.truncated
        if self.error_type:
            payload["error_type"] = self.error_type
        if self.error_message:
            payload["error_message"] = self.error_message[:_MAX_VALUE_CHARS]
        # ``default=str`` guarantees a line is emitted even if an argument
        # sneaks through redaction as a non-serialisable object; losing the
        # audit line would be worse than logging a repr.
        return json.dumps(payload, default=str, sort_keys=False)


class AuditLogger:
    """Writes :class:`AuditEvent` records as JSON lines."""

    def __init__(
        self,
        stream: IO[str] | None = None,
        *,
        actor: str = "mcp-client",
        clock: Callable[[], float] = time.perf_counter,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._stream = stream if stream is not None else sys.stderr
        if self._stream is sys.stdout:
            raise ValueError(
                "The audit log may not target stdout: stdout carries the MCP "
                "stdio transport and any extra bytes corrupt the JSON-RPC stream."
            )
        self._actor = actor
        self._clock = clock
        self._now = now or (lambda: datetime.now(UTC))

    @classmethod
    def from_path(
        cls, path: str | None, *, actor: str = "mcp-client"
    ) -> AuditLogger:
        """Open a file sink, or fall back to stderr when ``path`` is empty."""
        if not path:
            return cls(actor=actor)
        # Line-buffered append: an audit trail that is lost on crash is not an
        # audit trail.
        # Not a context manager on purpose: the handle lives for the life of
        # the process. buffering=1 is line buffering -- an audit trail lost in
        # a buffer on crash is not an audit trail.
        handle = open(path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115
        return cls(handle, actor=actor)

    def emit(self, event: AuditEvent) -> None:
        """Write one record. Logging failures never break a tool call."""
        try:
            self._stream.write(event.to_json(timestamp=self._now().isoformat()) + "\n")
            self._stream.flush()
        except Exception:  # pragma: no cover - defensive
            pass

    @asynccontextmanager
    async def tool_call(
        self, tool: str, arguments: Mapping[str, Any] | None = None
    ) -> AsyncIterator[AuditEvent]:
        """Time a tool call and emit exactly one audit record for it.

        The record is emitted on both the success and the failure path; an
        exception is re-raised after being recorded.
        """
        event = AuditEvent(
            tool=tool,
            actor=self._actor,
            arguments=redact(dict(arguments or {})),
        )
        started = self._clock()
        try:
            yield event
        except Exception as exc:
            event.outcome = "error"
            event.error_type = type(exc).__name__
            event.error_message = str(exc)
            raise
        finally:
            event.duration_ms = (self._clock() - started) * 1000.0
            self.emit(event)
