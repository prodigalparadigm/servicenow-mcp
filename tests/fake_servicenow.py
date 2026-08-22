"""An in-memory ServiceNow instance served through an ``httpx`` transport.

This is not a stub that returns canned dicts. It implements the parts of the
Table API the client actually depends on:

* ``sysparm_query`` encoded-query evaluation -- AND/OR grouping, the common
  operators, ``ORDERBY``/``ORDERBYDESC``, and dotted reference walks;
* ``sysparm_offset`` / ``sysparm_limit`` slicing, with ``X-Total-Count`` and a
  ``Link: rel="next"`` header;
* ``sysparm_fields`` projection, and ``sysparm_display_value`` /
  ``sysparm_exclude_reference_link`` rendering of reference and choice fields;
* auth enforcement for both basic and bearer credentials, plus the
  ``/oauth_token.do`` client-credentials endpoint;
* a scriptable fault queue, so 429/503/timeout/garbage-body behaviour can be
  driven deterministically.

Because it is mounted as a real ``httpx.MockTransport``, the production request
path runs unchanged: the same header assembly, retry loop, query encoding, and
response validation execute in tests as in production.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode

import httpx

__all__ = [
    "FakeServiceNow",
    "Fault",
    "Ref",
    "make_cis",
    "make_groups",
    "make_incidents",
]


@dataclass(frozen=True, slots=True)
class Ref:
    """A reference or choice field: a stored value plus a display label."""

    value: str
    display_value: str


@dataclass(slots=True)
class Fault:
    """A scripted failure to inject before the next real response."""

    #: HTTP status to return; ignored when ``exception`` is set.
    status: int = 429
    #: Value for the ``Retry-After`` header.
    retry_after: str | None = None
    #: Raw body to return instead of a valid envelope.
    body: str | None = None
    content_type: str = "application/json"
    #: Raise this instead of responding, to simulate a network failure.
    exception: Exception | None = None
    #: How many consecutive requests this fault applies to.
    times: int = 1
    #: Restrict the fault to requests whose path contains this substring.
    path_contains: str | None = None


@dataclass(slots=True)
class RecordedRequest:
    """One request as the fake saw it, for assertions."""

    method: str
    path: str
    params: dict[str, list[str]]
    headers: dict[str, str]
    body: Any

    def param(self, name: str) -> str | None:
        values = self.params.get(name)
        return values[0] if values else None

    def int_param(self, name: str) -> int | None:
        raw = self.param(name)
        return int(raw) if raw is not None and raw.lstrip("-").isdigit() else None


_TABLE_PATH = re.compile(r"^/api/now/table/(?P<table>[^/]+)(?:/(?P<sys_id>[^/]+))?/?$")

#: Longest-first, so ``!=`` is not parsed as ``=`` and ``>=`` not as ``>``.
_BINARY_OPERATORS: Sequence[str] = (
    "STARTSWITH",
    "ENDSWITH",
    "NOTLIKE",
    "LIKE",
    "NOTIN",
    "IN",
    "!=",
    ">=",
    "<=",
    "=",
    ">",
    "<",
)
_UNARY_OPERATORS: Sequence[str] = ("ISNOTEMPTY", "ISEMPTY")


class FakeServiceNow:
    """A programmable, in-memory ServiceNow instance."""

    def __init__(
        self,
        tables: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
        *,
        base_url: str = "https://example.service-now.com",
        username: str | None = None,
        password: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        access_token: str = "fake-access-token",
        token_expires_in: int | str | None = 1800,
        require_auth: bool = True,
        send_total_count: bool = True,
        next_sys_id: Callable[[], str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.tables: dict[str, list[dict[str, Any]]] = {
            name: [dict(r) for r in rows] for name, rows in (tables or {}).items()
        }
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.token_expires_in = token_expires_in
        self.require_auth = require_auth
        self.send_total_count = send_total_count

        self.requests: list[RecordedRequest] = []
        self.token_requests: list[dict[str, Any]] = []
        self._faults: list[Fault] = []
        self._counter = 0
        self._next_sys_id = next_sys_id or self._default_sys_id
        #: Set to a new value to make previously issued bearer tokens 401.
        self.rejected_tokens: set[str] = set()

    # -- setup ----------------------------------------------------------

    def _default_sys_id(self) -> str:
        self._counter += 1
        return f"{self._counter:032x}"

    def transport(self) -> httpx.MockTransport:
        """An ``httpx`` transport that routes into this fake."""
        return httpx.MockTransport(self._handle)

    def add_fault(self, fault: Fault) -> FakeServiceNow:
        """Queue a scripted failure. Faults are consumed in order."""
        self._faults.append(fault)
        return self

    def fail_next(
        self,
        times: int = 1,
        *,
        status: int = 429,
        retry_after: str | None = None,
        body: str | None = None,
        content_type: str = "application/json",
        exception: Exception | None = None,
        path_contains: str | None = None,
    ) -> FakeServiceNow:
        """Convenience wrapper over :meth:`add_fault`."""
        return self.add_fault(
            Fault(
                status=status,
                retry_after=retry_after,
                body=body,
                content_type=content_type,
                exception=exception,
                times=times,
                path_contains=path_contains,
            )
        )

    def rows(self, table: str) -> list[dict[str, Any]]:
        """Direct access to stored rows, for post-write assertions."""
        return self.tables.setdefault(table, [])

    @property
    def table_requests(self) -> list[RecordedRequest]:
        """Requests against the Table API, excluding token fetches."""
        return [r for r in self.requests if r.path.startswith("/api/now/table")]

    # -- request handling -----------------------------------------------

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        params = parse_qs(request.url.query.decode("utf-8"), keep_blank_values=True)
        body: Any = None
        if request.content:
            try:
                body = json.loads(request.content.decode("utf-8"))
            except ValueError:
                body = request.content.decode("utf-8", errors="replace")

        self.requests.append(
            RecordedRequest(
                method=request.method,
                path=path,
                params=params,
                headers={k.lower(): v for k, v in request.headers.items()},
                body=body,
            )
        )

        fault = self._take_fault(path)
        if fault is not None:
            if fault.exception is not None:
                raise fault.exception
            headers = {"Content-Type": fault.content_type}
            if fault.retry_after is not None:
                headers["Retry-After"] = fault.retry_after
            content = (
                fault.body
                if fault.body is not None
                else json.dumps(
                    {
                        "error": {
                            "message": f"Injected fault {fault.status}",
                            "detail": "fake",
                        },
                        "status": "failure",
                    }
                )
            )
            return httpx.Response(fault.status, headers=headers, content=content)

        if path == "/oauth_token.do":
            return self._handle_token(request)

        auth_error = self._check_auth(request)
        if auth_error is not None:
            return auth_error

        match = _TABLE_PATH.match(path)
        if match is None:
            return self._error(404, f"No route for {path}")

        table = match.group("table")
        sys_id = match.group("sys_id")

        if request.method == "GET":
            return (
                self._get_one(table, sys_id, params)
                if sys_id
                else self._query(table, params)
            )
        if request.method == "POST" and not sys_id:
            return self._create(table, body, params)
        if request.method in ("PATCH", "PUT") and sys_id:
            return self._update(table, sys_id, body, params)
        return self._error(405, f"{request.method} not allowed on {path}")

    def _take_fault(self, path: str) -> Fault | None:
        while self._faults:
            fault = self._faults[0]
            if fault.path_contains and fault.path_contains not in path:
                return None
            fault.times -= 1
            if fault.times <= 0:
                self._faults.pop(0)
            return fault
        return None

    # -- auth -----------------------------------------------------------

    def _handle_token(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode("utf-8"), keep_blank_values=True)
        flat = {k: v[0] for k, v in form.items()}
        self.token_requests.append(flat)
        if flat.get("grant_type") != "client_credentials":
            return httpx.Response(400, json={"error": "unsupported_grant_type"})
        if flat.get("client_id") != self.client_id or (
            flat.get("client_secret") != self.client_secret
        ):
            return httpx.Response(401, json={"error": "invalid_client"})
        payload: dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": "Bearer",
        }
        if self.token_expires_in is not None:
            payload["expires_in"] = self.token_expires_in
        return httpx.Response(200, json=payload)

    def _check_auth(self, request: httpx.Request) -> httpx.Response | None:
        if not self.require_auth:
            return None
        header = request.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return self._error(401, "Malformed basic credentials")
            user, _, pwd = decoded.partition(":")
            if user == self.username and pwd == self.password:
                return None
            return self._error(401, "User Not Authenticated")
        if header.startswith("Bearer "):
            token = header[7:]
            if token in self.rejected_tokens:
                return self._error(401, "Token expired")
            if token == self.access_token:
                return None
            return self._error(401, "Invalid token")
        return self._error(401, "Required to provide Auth information")

    # -- table operations -----------------------------------------------

    def _query(self, table: str, params: Mapping[str, list[str]]) -> httpx.Response:
        rows = self.tables.get(table, [])
        encoded = _first(params, "sysparm_query") or ""
        matched, order = _apply_query(rows, encoded)
        for field_name, descending in reversed(order):
            matched.sort(
                key=lambda r, f=field_name: _sort_key(_raw(r.get(f))),
                reverse=descending,
            )

        limit = _int(_first(params, "sysparm_limit"), default=10_000)
        offset = _int(_first(params, "sysparm_offset"), default=0)
        window = matched[offset : offset + limit]

        fields = _split_fields(_first(params, "sysparm_fields"))
        display = _first(params, "sysparm_display_value") or "false"
        exclude_link = (
            _first(params, "sysparm_exclude_reference_link") or "false"
        ).lower() == "true"
        rendered = [
            _render(row, fields, display=display, exclude_link=exclude_link)
            for row in window
        ]

        headers: dict[str, str] = {}
        if self.send_total_count:
            headers["X-Total-Count"] = str(len(matched))
        if offset + limit < len(matched):
            nxt = dict((k, v[0]) for k, v in params.items())
            nxt["sysparm_offset"] = str(offset + limit)
            headers["Link"] = (
                f'<{self.base_url}/api/now/table/{table}?{urlencode(nxt)}>; rel="next"'
            )
        return httpx.Response(200, json={"result": rendered}, headers=headers)

    def _get_one(
        self, table: str, sys_id: str, params: Mapping[str, list[str]]
    ) -> httpx.Response:
        for row in self.tables.get(table, []):
            if _raw(row.get("sys_id")) == sys_id:
                return httpx.Response(
                    200,
                    json={
                        "result": _render(
                            row,
                            _split_fields(_first(params, "sysparm_fields")),
                            display=_first(params, "sysparm_display_value") or "false",
                            exclude_link=(
                                _first(params, "sysparm_exclude_reference_link") or ""
                            ).lower()
                            == "true",
                        )
                    },
                )
        return self._error(404, "No Record found")

    def _create(
        self, table: str, body: Any, params: Mapping[str, list[str]]
    ) -> httpx.Response:
        if not isinstance(body, Mapping):
            return self._error(400, "Request body must be a JSON object")
        rows = self.tables.setdefault(table, [])
        record: dict[str, Any] = {
            "sys_id": self._next_sys_id(),
            "sys_updated_on": "2026-08-22 12:00:00",
            "opened_at": "2026-08-22 12:00:00",
            "active": "true",
            "state": Ref("1", "New"),
        }
        if table == "incident":
            record["number"] = f"INC{len(rows) + 900001:07d}"
        record.update(_resolve_write(self, dict(body)))
        rows.append(record)
        return httpx.Response(
            201,
            json={
                "result": _render(
                    record,
                    _split_fields(_first(params, "sysparm_fields")),
                    display=_first(params, "sysparm_display_value") or "false",
                    exclude_link=(
                        _first(params, "sysparm_exclude_reference_link") or ""
                    ).lower()
                    == "true",
                )
            },
        )

    def _update(
        self, table: str, sys_id: str, body: Any, params: Mapping[str, list[str]]
    ) -> httpx.Response:
        if not isinstance(body, Mapping):
            return self._error(400, "Request body must be a JSON object")
        for row in self.tables.get(table, []):
            if _raw(row.get("sys_id")) == sys_id:
                updates = _resolve_write(self, dict(body))
                # Journal fields append rather than replace, as ServiceNow does.
                for journal in ("work_notes", "comments"):
                    if journal in updates:
                        prior = _raw(row.get(journal))
                        updates[journal] = (
                            f"{prior}\n{updates[journal]}"
                            if prior
                            else updates[journal]
                        )
                row.update(updates)
                row["sys_updated_on"] = "2026-08-22 13:00:00"
                return httpx.Response(
                    200,
                    json={
                        "result": _render(
                            row,
                            _split_fields(_first(params, "sysparm_fields")),
                            display=_first(params, "sysparm_display_value") or "false",
                            exclude_link=(
                                _first(params, "sysparm_exclude_reference_link") or ""
                            ).lower()
                            == "true",
                        )
                    },
                )
        return self._error(404, "No Record found")

    @staticmethod
    def _error(status: int, message: str) -> httpx.Response:
        return httpx.Response(
            status,
            json={"error": {"message": message, "detail": None}, "status": "failure"},
        )


# -- rendering ----------------------------------------------------------


def _raw(value: Any) -> str:
    """The stored value of a field, ignoring its display label."""
    if isinstance(value, Ref):
        return value.value
    return "" if value is None else str(value)


def _display(value: Any) -> str:
    if isinstance(value, Ref):
        return value.display_value
    return "" if value is None else str(value)


def _render(
    row: Mapping[str, Any],
    fields: Sequence[str] | None,
    *,
    display: str,
    exclude_link: str | bool,
) -> dict[str, Any]:
    """Render one stored row the way the Table API would."""
    keys = fields if fields else list(row.keys())
    out: dict[str, Any] = {}
    for key in keys:
        if key not in row:
            # ServiceNow returns "" for a requested-but-unset column.
            out[key] = ""
            continue
        value = row[key]
        if display == "all":
            out[key] = {"display_value": _display(value), "value": _raw(value)}
        elif display == "true":
            out[key] = _display(value)
        elif isinstance(value, Ref) and not exclude_link:
            out[key] = {
                "link": f"https://example.service-now.com/api/now/table/x/{value.value}",
                "value": value.value,
            }
        else:
            out[key] = _raw(value)
    return out


def _split_fields(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    return [f for f in (part.strip() for part in raw.split(",")) if f]


def _first(params: Mapping[str, list[str]], key: str) -> str | None:
    values = params.get(key)
    return values[0] if values else None


def _int(raw: str | None, *, default: int) -> int:
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _sort_key(value: str) -> tuple[int, float, str]:
    """Sort numerics numerically, everything else lexically, blanks last."""
    if value == "":
        return (2, 0.0, "")
    try:
        return (0, float(value), "")
    except ValueError:
        return (1, 0.0, value)


# -- encoded-query evaluation -------------------------------------------


def _apply_query(
    rows: Sequence[Mapping[str, Any]], encoded: str
) -> tuple[list[dict[str, Any]], list[tuple[str, bool]]]:
    """Evaluate a ``sysparm_query`` against stored rows.

    Returns the matching rows and the requested sort order. Conditions are
    AND-ed; a term prefixed with ``OR`` is OR-ed into the immediately preceding
    condition group, which is ServiceNow's actual precedence rule.
    """
    order: list[tuple[str, bool]] = []
    groups: list[list[str]] = []

    for token in (t for t in encoded.split("^") if t):
        if token.startswith("ORDERBYDESC"):
            order.append((token[len("ORDERBYDESC") :], True))
            continue
        if token.startswith("ORDERBY"):
            order.append((token[len("ORDERBY") :], False))
            continue
        if token.startswith("OR") and groups and _looks_like_condition(token[2:]):
            groups[-1].append(token[2:])
            continue
        groups.append([token])

    matched = [
        dict(row)
        for row in rows
        if all(any(_evaluate(row, cond) for cond in group) for group in groups)
    ]
    return matched, order


def _looks_like_condition(token: str) -> bool:
    return any(op in token for op in _BINARY_OPERATORS) or any(
        token.endswith(op) for op in _UNARY_OPERATORS
    )


def _field_value(row: Mapping[str, Any], field_name: str) -> str:
    """Resolve a field, including a one-hop dotted reference walk.

    ``assignment_group.name`` resolves to the display label of the stored
    reference, which is how a real instance dereferences it for the common case
    of walking to the referenced record's display column.
    """
    if "." in field_name:
        base, _, attribute = field_name.partition(".")
        value = row.get(base)
        if isinstance(value, Ref):
            # ``.name``/``.user_name`` walk to the display column.
            return value.display_value if attribute in ("name", "user_name") else ""
        return _raw(value)
    return _raw(row.get(field_name))


def _evaluate(row: Mapping[str, Any], condition: str) -> bool:
    for op in _UNARY_OPERATORS:
        if condition.endswith(op):
            value = _field_value(row, condition[: -len(op)])
            return (value == "") if op == "ISEMPTY" else (value != "")

    # Pick the *earliest* operator occurrence, breaking ties by length. Scanning
    # the operator table in order instead would misparse "number=INC0000004":
    # "IN" appears at index 7 (inside the value) and would win over "=" at 6.
    best: tuple[int, int, str] | None = None
    for op in _BINARY_OPERATORS:
        index = condition.find(op)
        if index <= 0:
            continue
        candidate = (index, -len(op), op)
        if best is None or candidate < best:
            best = candidate
    if best is None:
        return True

    index, _, op = best
    value = _field_value(row, condition[:index])
    return _compare(value, op, condition[index + len(op) :])


def _compare(value: str, op: str, operand: str) -> bool:
    lowered_value, lowered_operand = value.lower(), operand.lower()
    if op == "=":
        return value == operand
    if op == "!=":
        return value != operand
    if op == "LIKE":
        return lowered_operand in lowered_value
    if op == "NOTLIKE":
        return lowered_operand not in lowered_value
    if op == "STARTSWITH":
        return lowered_value.startswith(lowered_operand)
    if op == "ENDSWITH":
        return lowered_value.endswith(lowered_operand)
    if op == "IN":
        return value in operand.split(",")
    if op == "NOTIN":
        return value not in operand.split(",")
    if op in (">", "<", ">=", "<="):
        left, right = _sort_key(value), _sort_key(operand)
        if op == ">":
            return left > right
        if op == "<":
            return left < right
        if op == ">=":
            return left >= right
        return left <= right
    return False  # pragma: no cover - operator table is exhaustive


def _resolve_write(fake: FakeServiceNow, payload: dict[str, Any]) -> dict[str, Any]:
    """Turn written sys_ids into stored ``Ref`` values where we can.

    A real instance stores a reference field as a sys_id and renders the
    referenced record's display column on read; reproducing that is what makes
    the projection tests meaningful.
    """
    resolved: dict[str, Any] = {}
    reference_tables = {
        "assignment_group": "sys_user_group",
        "caller_id": "sys_user",
        "assigned_to": "sys_user",
        "cmdb_ci": "cmdb_ci",
    }
    for key, value in payload.items():
        table = reference_tables.get(key)
        if table:
            for row in fake.tables.get(table, []):
                if _raw(row.get("sys_id")) == str(value):
                    resolved[key] = Ref(str(value), _raw(row.get("name")))
                    break
            else:
                resolved[key] = Ref(str(value), str(value))
            continue
        if key == "state":
            labels = {
                "1": "New",
                "2": "In Progress",
                "3": "On Hold",
                "6": "Resolved",
                "7": "Closed",
                "8": "Canceled",
            }
            resolved[key] = Ref(str(value), labels.get(str(value), str(value)))
            continue
        resolved[key] = value
    return resolved


# -- fixture builders ---------------------------------------------------


def make_incidents(
    count: int,
    *,
    group: str = "Network Support",
    group_sys_id: str = "grp-network",
    start: int = 1,
) -> list[dict[str, Any]]:
    """Generate ``count`` incident rows with varied, queryable field values."""
    states = [("1", "New"), ("2", "In Progress"), ("6", "Resolved")]
    rows: list[dict[str, Any]] = []
    for index in range(start, start + count):
        state_value, state_label = states[index % len(states)]
        rows.append(
            {
                "sys_id": f"inc-sys-{index:04d}",
                "number": f"INC{index:07d}",
                "short_description": f"Incident {index}: VPN tunnel flapping",
                "description": f"Long form detail for incident {index}. " * 3,
                "state": Ref(state_value, state_label),
                "active": "true" if state_value != "6" else "false",
                "priority": Ref(str((index % 5) + 1), f"{(index % 5) + 1} - Ranked"),
                "urgency": Ref("2", "2 - Medium"),
                "impact": Ref("2", "2 - Medium"),
                "category": "network",
                "assignment_group": Ref(group_sys_id, group),
                "assigned_to": Ref(f"usr-{index:04d}", f"Agent {index}"),
                "caller_id": Ref("usr-caller", "Dana Reyes"),
                "opened_at": f"2026-08-{(index % 28) + 1:02d} 09:00:00",
                "sys_updated_on": f"2026-08-{(index % 28) + 1:02d} 10:30:00",
                # Columns outside the allowlist. Present so projection tests
                # prove they are dropped rather than merely absent.
                "u_cost_centre": "CC-99201",
                "sys_domain": Ref("global", "global"),
                "u_caller_phone": "+1-555-0100",
                "sys_created_by": "integration.user",
            }
        )
    return rows


def make_groups(names: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Assignment-group rows."""
    names = list(names or ["Network Support", "Database Ops", "Service Desk"])
    return [
        {
            "sys_id": f"grp-{name.split()[0].lower()}",
            "name": name,
            "description": f"{name} queue",
            "email": f"{name.split()[0].lower()}@example.invalid",
            "active": "true",
            "type": "itil",
            "manager": Ref("usr-mgr", "Sam Okafor"),
            "u_internal_notes": "should never be returned",
        }
        for name in names
    ]


def make_cis() -> list[dict[str, Any]]:
    """CMDB rows, including one pair that only matches fuzzily."""
    return [
        {
            "sys_id": "ci-app-prod-04",
            "name": "app-prod-04",
            "sys_class_name": "cmdb_ci_linux_server",
            "operational_status": Ref("1", "Operational"),
            "install_status": Ref("1", "Installed"),
            "environment": "production",
            "support_group": Ref("grp-network", "Network Support"),
            "managed_by": Ref("usr-mgr", "Sam Okafor"),
            "owned_by": Ref("usr-owner", "Priya Nandakumar"),
            "location": Ref("loc-dc1", "DC1 Frankfurt"),
            "ip_address": "10.0.0.4",
            "serial_number": "SN-SHOULD-NOT-LEAK",
        },
        {
            "sys_id": "ci-app-prod-05",
            "name": "app-prod-05",
            "sys_class_name": "cmdb_ci_linux_server",
            "operational_status": Ref("1", "Operational"),
            "environment": "production",
            "support_group": Ref("grp-database", "Database Ops"),
            "ip_address": "10.0.0.5",
        },
        {
            "sys_id": "ci-orphan-01",
            "name": "orphan-host-01",
            "sys_class_name": "cmdb_ci_linux_server",
            "environment": "lab",
        },
    ]
