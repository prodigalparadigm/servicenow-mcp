"""Encoded-query construction, including the injection guard."""

from __future__ import annotations

import pytest

from servicenow_mcp.query import QueryBuilder, QuerySyntaxError, sanitize_operand


def test_conditions_are_joined_with_the_and_delimiter():
    query = (
        QueryBuilder().where("active", "=", True).where("priority", "<=", 2).render()
    )
    assert query == "active=true^priority<=2"


def test_booleans_render_as_servicenow_booleans():
    assert QueryBuilder().where("active", "=", False).render() == "active=false"


def test_order_by_is_appended_last():
    query = (
        QueryBuilder()
        .where("state", "=", "2")
        .order_by("sys_updated_on", descending=True)
        .render()
    )
    assert query == "state=2^ORDERBYDESCsys_updated_on"


def test_order_by_spec_shorthand():
    assert QueryBuilder().order_by_spec("-number").render() == "ORDERBYDESCnumber"
    assert QueryBuilder().order_by_spec("number").render() == "ORDERBYnumber"
    assert QueryBuilder().order_by_spec(None).render() == ""


def test_unary_operators_take_no_operand():
    assert (
        QueryBuilder().where("assigned_to", "ISEMPTY").render() == "assigned_toISEMPTY"
    )


def test_dotted_reference_walks_are_allowed():
    query = (
        QueryBuilder().where("assignment_group.name", "=", "Network Support").render()
    )
    assert query == "assignment_group.name=Network Support"


def test_where_in_joins_with_commas():
    assert QueryBuilder().where_in("state", ["1", "2", "3"]).render() == "stateIN1,2,3"


def test_where_in_ignores_an_empty_list():
    assert QueryBuilder().where_in("state", []).render() == ""


def test_where_in_rejects_a_comma_in_an_operand():
    with pytest.raises(QuerySyntaxError, match="list separator"):
        QueryBuilder().where_in("category", ["a,b"])


def test_empty_builder_renders_empty():
    builder = QueryBuilder()
    assert builder.render() == ""
    assert not builder


@pytest.mark.parametrize("payload", ["a^b", "a\nb", "a\rb"])
def test_delimiters_in_an_operand_are_refused(payload):
    with pytest.raises(QuerySyntaxError, match="may not contain"):
        sanitize_operand(payload)


def test_injection_through_a_filter_value_cannot_rewrite_the_query():
    with pytest.raises(QuerySyntaxError):
        QueryBuilder().where("short_description", "LIKE", "x^active=false")


def test_unknown_operator_is_rejected_with_the_supported_list():
    with pytest.raises(QuerySyntaxError, match="Unsupported operator"):
        QueryBuilder().where("state", "~=", "2")


@pytest.mark.parametrize("field", ["", "state;drop", "a b", "state^x", "../etc"])
def test_invalid_field_names_are_rejected(field):
    with pytest.raises(QuerySyntaxError, match="Invalid field name"):
        QueryBuilder().where(field, "=", "1")


def test_raw_is_the_only_path_that_accepts_a_delimiter():
    query = (
        QueryBuilder().where("active", "=", True).raw("^priority=1^ORstate=2").render()
    )
    assert query == "active=true^priority=1^ORstate=2"


def test_raw_ignores_empty_input():
    assert QueryBuilder().raw(None).raw("").raw("  ").render() == ""


def test_terms_are_exposed_for_inspection():
    builder = QueryBuilder().where("a", "=", "1").where("b", "=", "2")
    assert builder.terms == ("a=1", "b=2")
