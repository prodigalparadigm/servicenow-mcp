"""ServiceNow Table API client: pagination, record caps, response validation.

The Table API paginates with ``sysparm_offset`` / ``sysparm_limit`` and reports
the unfiltered match count in the ``X-Total-Count`` response header. This client
turns that into a single bounded call:

* the caller states how many records it wants; the client fetches pages until
  it has them, the source is exhausted, or the configured hard cap is reached;
* the cap is enforced *before* the first request, so an agent asking for 50,000
  incidents issues a handful of requests, not a thousand;
* ``has_more`` is answered without an extra round trip when ``X-Total-Count`` is
  present, and with a one-record probe page when it is not.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import quote

from .config import Settings
from .errors import MalformedResponseError, RecordNotFoundError, ServiceNowAPIError
from .transport import ServiceNowTransport

__all__ = ["Page", "ServiceNowClient"]

#: ``sysparm_display_value=true`` makes ServiceNow resolve reference and choice
#: fields to their labels ("In Progress", "Network Support") instead of sys_ids
#: and integer codes. Combined with ``sysparm_exclude_reference_link=true`` this
#: roughly halves payload size and removes an entire class of follow-up lookups
#: the model would otherwise have to make to render a human-readable answer.
_DISPLAY_PARAMS: Final[Mapping[str, str]] = {
    "sysparm_display_value": "true",
    "sysparm_exclude_reference_link": "true",
}


@dataclass(slots=True)
class Page:
    """A bounded slice of a table."""

    records: list[dict[str, Any]] = field(default_factory=list)
    offset: int = 0
    #: Records the caller asked for, before the cap was applied.
    requested_limit: int = 0
    #: Records the client was actually allowed to return.
    effective_limit: int = 0
    #: True when ``requested_limit`` exceeded the configured hard cap.
    capped: bool = False
    #: True when more records match the query beyond what was returned.
    has_more: bool = False
    #: Total matching records, when the instance reported ``X-Total-Count``.
    total_available: int | None = None
    #: Underlying Table API requests this page cost.
    requests: int = 0

    @property
    def next_offset(self) -> int | None:
        """Offset to pass in to continue, or None when the page is the last."""
        return self.offset + len(self.records) if self.has_more else None


class ServiceNowClient:
    """Typed access to the Table API on top of :class:`ServiceNowTransport`."""

    def __init__(self, settings: Settings, transport: ServiceNowTransport) -> None:
        self._settings = settings
        self._transport = transport

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def transport(self) -> ServiceNowTransport:
        return self._transport

    async def aclose(self) -> None:
        await self._transport.aclose()

    def _table_url(self, table: str, sys_id: str | None = None) -> str:
        # ``quote`` guards against a table or sys_id argument that has been
        # threaded through from model input containing path separators.
        base = f"{self._settings.table_api_root}/{quote(table, safe='')}"
        return f"{base}/{quote(sys_id, safe='')}" if sys_id else base

    # -- reads ----------------------------------------------------------

    async def query_table(
        self,
        table: str,
        *,
        encoded_query: str = "",
        fields: Sequence[str],
        limit: int,
        offset: int = 0,
    ) -> Page:
        """Fetch up to ``limit`` records, paginating as needed.

        Args:
            table: Table name, e.g. ``"incident"``.
            encoded_query: A rendered ``sysparm_query``. Empty means no filter.
            fields: Allowlist pushed down as ``sysparm_fields`` so unwanted
                columns are never transferred.
            limit: Records wanted. Silently clamped to ``max_records``; the
                returned page reports whether clamping happened.
            offset: Starting ``sysparm_offset``.

        Raises:
            MalformedResponseError: the body was not ``{"result": [...]}``.
        """
        requested_limit = max(int(limit), 0)
        effective_limit = min(requested_limit, self._settings.max_records)
        capped = requested_limit > effective_limit
        offset = max(int(offset), 0)

        page = Page(
            offset=offset,
            requested_limit=requested_limit,
            effective_limit=effective_limit,
            capped=capped,
        )
        if effective_limit == 0:
            return page

        page_size = self._settings.effective_page_size()
        # Target one extra record so "is there more?" can be answered without
        # guessing when the instance omits X-Total-Count.
        target = effective_limit + 1
        records: list[dict[str, Any]] = []
        started_before = self._transport.stats.requests

        while len(records) < target:
            batch_size = min(page_size, target - len(records))
            params: dict[str, Any] = {
                "sysparm_limit": batch_size,
                "sysparm_offset": offset + len(records),
                "sysparm_fields": ",".join(fields),
                **_DISPLAY_PARAMS,
            }
            if encoded_query:
                params["sysparm_query"] = encoded_query

            payload, headers = await self._transport.request_json(
                "GET", self._table_url(table), params=params
            )
            batch = _extract_result_list(payload, table)
            records.extend(batch)

            total = _parse_total_count(headers.get("X-Total-Count"))
            if total is not None:
                page.total_available = total

            if len(batch) < batch_size:
                # A short page is the instance telling us the result set ended.
                break
            if total is not None and offset + len(records) >= total:
                # Saves the probe request entirely on instances that report it.
                break

        page.requests = self._transport.stats.requests - started_before
        page.has_more = len(records) > effective_limit
        page.records = records[:effective_limit]
        if page.total_available is not None and not page.has_more:
            page.has_more = offset + len(page.records) < page.total_available
        return page

    async def get_record(
        self, table: str, sys_id: str, *, fields: Sequence[str]
    ) -> dict[str, Any]:
        """Fetch one record by sys_id.

        Raises:
            RecordNotFoundError: no such record. The Table API signals this
                two different ways -- a 404 for a well-formed sys_id that
                matches nothing, and a 200 with an empty result on some
                versions -- so both are normalised to one exception.
        """
        try:
            payload, _ = await self._transport.request_json(
                "GET",
                self._table_url(table, sys_id),
                params={"sysparm_fields": ",".join(fields), **_DISPLAY_PARAMS},
            )
        except ServiceNowAPIError as exc:
            if exc.status_code == 404:
                raise RecordNotFoundError(
                    f"No {table} record with sys_id {sys_id!r}"
                ) from exc
            raise
        record = _extract_result_object(payload, table)
        if record is None:
            raise RecordNotFoundError(f"No {table} record with sys_id {sys_id!r}")
        return record

    async def find_one(
        self,
        table: str,
        *,
        encoded_query: str,
        fields: Sequence[str],
    ) -> dict[str, Any] | None:
        """Fetch the first record matching a query, or None."""
        page = await self.query_table(
            table, encoded_query=encoded_query, fields=fields, limit=1
        )
        return page.records[0] if page.records else None

    # -- writes ---------------------------------------------------------

    async def create_record(
        self, table: str, payload: Mapping[str, Any], *, fields: Sequence[str]
    ) -> dict[str, Any]:
        """POST a new record and return the created row, projected server-side.

        Read-only enforcement lives one layer up, in the service; this method
        is the unconditional mechanism.
        """
        body, _ = await self._transport.request_json(
            "POST",
            self._table_url(table),
            params={"sysparm_fields": ",".join(fields), **_DISPLAY_PARAMS},
            json_body=payload,
        )
        record = _extract_result_object(body, table)
        if record is None:
            raise MalformedResponseError(
                f"Creating a {table} record succeeded at the HTTP layer but the "
                "response contained no record; the write may or may not have "
                "been applied. Verify before retrying."
            )
        return record

    async def update_record(
        self,
        table: str,
        sys_id: str,
        payload: Mapping[str, Any],
        *,
        fields: Sequence[str],
    ) -> dict[str, Any]:
        """PATCH an existing record and return the updated row."""
        body, _ = await self._transport.request_json(
            "PATCH",
            self._table_url(table, sys_id),
            params={"sysparm_fields": ",".join(fields), **_DISPLAY_PARAMS},
            json_body=payload,
        )
        record = _extract_result_object(body, table)
        if record is None:
            raise MalformedResponseError(
                f"Updating {table}/{sys_id} returned no record body."
            )
        return record


# -- payload validation -------------------------------------------------


def _extract_result_list(payload: Any, table: str) -> list[dict[str, Any]]:
    """Pull ``result`` out of a list response, rejecting anything else.

    The Table API contract is ``{"result": [ {...}, ... ]}``. Every deviation
    seen in practice -- a bare list from a scripted endpoint, an object where a
    list belongs, string records -- is a bug somewhere upstream, and guessing
    at the caller's behalf hides it.
    """
    if payload is None:
        raise MalformedResponseError(
            f"ServiceNow returned an empty body for a {table} query; expected "
            'a {"result": [...]} object.'
        )
    if not isinstance(payload, Mapping):
        raise MalformedResponseError(
            f"Expected a JSON object from the {table} table, got "
            f"{type(payload).__name__}."
        )
    if "result" not in payload:
        keys = ", ".join(sorted(str(k) for k in payload)) or "<none>"
        raise MalformedResponseError(
            f"Response for the {table} table has no 'result' key. Keys present: {keys}"
        )
    result = payload["result"]
    if isinstance(result, Mapping):
        raise MalformedResponseError(
            f"Expected a list of {table} records but got a single object; a "
            "query against the table collection should never return one."
        )
    if not isinstance(result, list):
        raise MalformedResponseError(
            f"Expected a list of {table} records, got {type(result).__name__}."
        )
    for index, record in enumerate(result):
        if not isinstance(record, Mapping):
            raise MalformedResponseError(
                f"Record {index} of the {table} result is a "
                f"{type(record).__name__}, not an object."
            )
    return [dict(record) for record in result]


def _extract_result_object(payload: Any, table: str) -> dict[str, Any] | None:
    """Pull ``result`` out of a single-record response.

    Returns None when the instance reports "no such record" the way it does for
    a sys_id lookup miss: an empty result. Raises for structurally wrong bodies.
    """
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise MalformedResponseError(
            f"Expected a JSON object from the {table} table, got "
            f"{type(payload).__name__}."
        )
    if "result" not in payload:
        keys = ", ".join(sorted(str(k) for k in payload)) or "<none>"
        raise MalformedResponseError(
            f"Response for the {table} table has no 'result' key. Keys present: {keys}"
        )
    result = payload["result"]
    if result in (None, "", [], {}):
        return None
    if isinstance(result, list):
        first = result[0]
        if not isinstance(first, Mapping):
            raise MalformedResponseError(
                f"Expected a {table} record object, got {type(first).__name__}."
            )
        return dict(first)
    if not isinstance(result, Mapping):
        raise MalformedResponseError(
            f"Expected a {table} record object, got {type(result).__name__}."
        )
    return dict(result)


def _parse_total_count(raw: str | None) -> int | None:
    """Read ``X-Total-Count``, ignoring a header that is not a count."""
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None
