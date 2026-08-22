"""Helpers for building ServiceNow encoded queries.

ServiceNow's encoded-query grammar is positional and delimiter-based
(``field=value^field2!=value2^ORDERBYDESCsys_updated_on``) with no escape
sequence for the ``^`` delimiter. That makes naive string concatenation of
model-supplied values a query-injection hazard: a caller who passes
``short_description`` of ``x^active=false`` silently rewrites the filter.

This module builds conditions from typed parts and rejects operands that would
break out of their own term.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Final

from .errors import ServiceNowMCPError

__all__ = ["QueryBuilder", "QuerySyntaxError", "sanitize_operand"]

#: Characters that terminate or restructure a term. There is no escape for
#: them in the encoded-query grammar, so operands containing them are rejected
#: rather than mangled.
_FORBIDDEN_OPERAND_CHARS: Final[tuple[str, ...]] = ("^", "\n", "\r")

_ALLOWED_OPERATORS: Final[frozenset[str]] = frozenset(
    {
        "=",
        "!=",
        ">",
        ">=",
        "<",
        "<=",
        "LIKE",
        "NOTLIKE",
        "STARTSWITH",
        "ENDSWITH",
        "IN",
        "NOTIN",
        "ISEMPTY",
        "ISNOTEMPTY",
    }
)

#: Operators that take no operand.
_UNARY_OPERATORS: Final[frozenset[str]] = frozenset({"ISEMPTY", "ISNOTEMPTY"})

#: Conservative field-name shape: ServiceNow allows dotted reference walks
#: (``assignment_group.name``) but nothing exotic.
_FIELD_CHARS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_."
)


class QuerySyntaxError(ServiceNowMCPError):
    """A field name or operand cannot be expressed safely in an encoded query."""


def sanitize_operand(value: Any) -> str:
    """Validate one operand, returning its string form.

    Raises:
        QuerySyntaxError: if the value contains a delimiter that would let it
            escape its own condition.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    for char in _FORBIDDEN_OPERAND_CHARS:
        if char in text:
            raise QuerySyntaxError(
                f"Filter value may not contain {char!r}: ServiceNow encoded "
                "queries have no escape for it, so the value would change the "
                "meaning of the query. Rephrase the filter."
            )
    return text


def _validate_field(field: str) -> str:
    if not field or not set(field) <= _FIELD_CHARS:
        raise QuerySyntaxError(
            f"Invalid field name {field!r}; expected letters, digits, "
            "underscores, and dots only."
        )
    return field


class QueryBuilder:
    """Accumulates AND-ed conditions and an optional sort, then renders."""

    def __init__(self) -> None:
        self._terms: list[str] = []
        self._order: list[str] = []

    def where(self, field: str, operator: str, value: Any = None) -> QueryBuilder:
        """Add one condition.

        Args:
            field: Column name, optionally a dotted reference walk.
            operator: One of the supported encoded-query operators.
            value: Operand; ignored for ``ISEMPTY``/``ISNOTEMPTY``.
        """
        field = _validate_field(field)
        operator = operator.upper() if operator.isalpha() else operator
        if operator not in _ALLOWED_OPERATORS:
            raise QuerySyntaxError(
                f"Unsupported operator {operator!r}; supported: "
                + ", ".join(sorted(_ALLOWED_OPERATORS))
            )
        if operator in _UNARY_OPERATORS:
            self._terms.append(f"{field}{operator}")
        else:
            self._terms.append(f"{field}{operator}{sanitize_operand(value)}")
        return self

    def where_in(self, field: str, values: Iterable[Any]) -> QueryBuilder:
        """Add an ``IN`` condition. Empty iterables are ignored."""
        rendered = [sanitize_operand(v) for v in values]
        if not rendered:
            return self
        for item in rendered:
            if "," in item:
                raise QuerySyntaxError(
                    "IN operands may not contain a comma; it is the list "
                    f"separator. Offending value: {item!r}"
                )
        return self.where(field, "IN", ",".join(rendered))

    def raw(self, encoded: str | None) -> QueryBuilder:
        """Append a caller-supplied encoded query fragment verbatim.

        This is the escape hatch for filters the typed helpers do not cover.
        It is intentionally the only path that accepts ``^``, and it is only
        reachable from a tool parameter that is documented as such -- so an
        operator reading the audit log can see exactly when raw query text was
        accepted from the model.
        """
        if encoded:
            fragment = encoded.strip().strip("^")
            if fragment:
                self._terms.append(fragment)
        return self

    def order_by(self, field: str, *, descending: bool = False) -> QueryBuilder:
        """Add a sort key. Multiple calls produce a compound sort."""
        field = _validate_field(field)
        self._order.append(f"ORDERBY{'DESC' if descending else ''}{field}")
        return self

    def order_by_spec(self, spec: str | None) -> QueryBuilder:
        """Apply a ``"-field"`` / ``"field"`` sort spec, if given."""
        if not spec:
            return self
        spec = spec.strip()
        if spec.startswith("-"):
            return self.order_by(spec[1:], descending=True)
        return self.order_by(spec)

    def render(self) -> str:
        """Render the encoded query. Empty when no conditions were added."""
        return "^".join([*self._terms, *self._order])

    def __bool__(self) -> bool:
        return bool(self._terms or self._order)

    @property
    def terms(self) -> Sequence[str]:
        return tuple(self._terms)
