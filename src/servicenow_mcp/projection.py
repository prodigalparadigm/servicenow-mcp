"""Field allowlists and record projection.

A stock ``incident`` table has roughly 180 columns. Returning all of them is
wrong for two independent reasons:

1. **Context economy.** Fifty incidents at ~180 fields each is tens of
   thousands of tokens of mostly-empty ``u_*`` custom columns, sys metadata,
   and duplicated reference links. The model reasons worse, not better, with
   that in its window, and the caller pays for every token.
2. **Data minimisation.** Incident records routinely carry caller phone
   numbers, free-text descriptions with account identifiers, and attachment
   metadata. An allowlist is an auditable, reviewable statement of exactly
   what leaves the customer's boundary -- something a security review can read
   in one screen. A denylist is not, because the next plugin install adds
   columns nobody vetted.

The allowlists are also pushed down to the wire as ``sysparm_fields``, so the
unwanted columns are never transferred at all rather than fetched and dropped.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

__all__ = [
    "INCIDENT_SUMMARY_FIELDS",
    "INCIDENT_DETAIL_FIELDS",
    "ASSIGNMENT_GROUP_FIELDS",
    "CMDB_CI_FIELDS",
    "TRUNCATION_SUFFIX",
    "project_record",
    "project_records",
]

#: Returned by ``search_incidents``. Deliberately excludes the long free-text
#: ``description`` and the journal fields: a list view needs enough to triage
#: and pick, not enough to read.
INCIDENT_SUMMARY_FIELDS: Final[tuple[str, ...]] = (
    "sys_id",
    "number",
    "short_description",
    "state",
    "priority",
    "urgency",
    "impact",
    "category",
    "assignment_group",
    "assigned_to",
    "caller_id",
    "opened_at",
    "sys_updated_on",
)

#: Returned by ``get_incident``. Adds the narrative fields, which are worth
#: their token cost for exactly one record at a time.
INCIDENT_DETAIL_FIELDS: Final[tuple[str, ...]] = INCIDENT_SUMMARY_FIELDS + (
    "description",
    "close_code",
    "close_notes",
    "resolved_at",
    "resolved_by",
    "cmdb_ci",
    "correlation_id",
    "comments",
    "work_notes",
)

ASSIGNMENT_GROUP_FIELDS: Final[tuple[str, ...]] = (
    "sys_id",
    "name",
    "description",
    "email",
    "manager",
    "parent",
    "active",
    "type",
)

#: CMDB projection for the ownership lookup. Intentionally omits IP addresses,
#: serial numbers, and asset/financial columns: "who do I page about this box"
#: does not require them, and they are the fields most likely to be regulated.
CMDB_CI_FIELDS: Final[tuple[str, ...]] = (
    "sys_id",
    "name",
    "sys_class_name",
    "operational_status",
    "install_status",
    "environment",
    "support_group",
    "managed_by",
    "owned_by",
    "assigned_to",
    "assignment_group",
    "location",
    "company",
    "comments",
)

TRUNCATION_SUFFIX: Final[str] = " ...[truncated]"

#: Per-field character budgets. Journals in particular grow without bound; a
#: five-year-old P3 can carry hundreds of kilobytes of work notes.
_FIELD_CHAR_LIMITS: Final[Mapping[str, int]] = {
    "description": 2_000,
    "comments": 4_000,
    "work_notes": 4_000,
    "close_notes": 2_000,
    "short_description": 300,
}

#: Applied to any allowlisted field without a specific budget.
_DEFAULT_CHAR_LIMIT: Final[int] = 500


def _coerce_scalar(value: Any) -> Any:
    """Flatten ServiceNow's reference-field shapes to a plain scalar.

    With ``sysparm_display_value=true`` a reference comes back as a display
    string, but instances configured for ``all`` (or older ones) return
    ``{"display_value": ..., "value": ...}``, and with reference links enabled
    they return ``{"link": ..., "value": ...}``. Normalising here means the
    model always sees one shape regardless of instance configuration.
    """
    if isinstance(value, Mapping):
        for key in ("display_value", "value", "link"):
            if key in value:
                inner = value[key]
                return inner if isinstance(inner, (str, int, float, bool)) else str(inner)
        return ""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Sequence):
        return ", ".join(str(_coerce_scalar(item)) for item in value)
    return str(value)


def _truncate(field: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    limit = _FIELD_CHAR_LIMITS.get(field, _DEFAULT_CHAR_LIMIT)
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + TRUNCATION_SUFFIX


def project_record(
    record: Mapping[str, Any],
    fields: Iterable[str],
    *,
    drop_empty: bool = True,
) -> dict[str, Any]:
    """Reduce one raw record to the allowlisted, normalised, truncated form.

    Args:
        record: A raw Table API record.
        fields: The allowlist for this table.
        drop_empty: Omit keys whose value is empty. ServiceNow returns ``""``
            for every unset column; carrying those into the model's context is
            pure noise, and their absence is unambiguous.

    Returns:
        A new dict containing only allowlisted keys. Unknown keys present in
        ``record`` are discarded; missing allowlisted keys are simply absent.
    """
    projected: dict[str, Any] = {}
    for field in fields:
        if field not in record:
            continue
        value = _truncate(field, _coerce_scalar(record[field]))
        if drop_empty and (value == "" or value is None):
            continue
        projected[field] = value
    return projected


def project_records(
    records: Iterable[Mapping[str, Any]],
    fields: Iterable[str],
    *,
    drop_empty: bool = True,
) -> list[dict[str, Any]]:
    """Project a sequence of records. ``fields`` is materialised once."""
    allowlist = tuple(fields)
    return [project_record(r, allowlist, drop_empty=drop_empty) for r in records]
