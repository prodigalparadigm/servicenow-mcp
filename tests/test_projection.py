"""Field allowlists: what leaves the instance, and what never gets fetched."""

from __future__ import annotations

import pytest

from servicenow_mcp.projection import (
    ASSIGNMENT_GROUP_FIELDS,
    CMDB_CI_FIELDS,
    INCIDENT_DETAIL_FIELDS,
    INCIDENT_SUMMARY_FIELDS,
    TRUNCATION_SUFFIX,
    project_record,
)


async def test_search_returns_only_allowlisted_fields(make_service):
    service = make_service()
    result = await service.search_incidents(limit=5)

    allowed = set(INCIDENT_SUMMARY_FIELDS)
    for incident in result["incidents"]:
        assert set(incident) <= allowed, set(incident) - allowed


async def test_columns_outside_the_allowlist_never_reach_the_model(make_service):
    """The fixture rows carry custom and PII-ish columns; none may appear."""
    service = make_service()
    result = await service.search_incidents(limit=5)

    forbidden = {"u_cost_centre", "u_caller_phone", "sys_domain", "sys_created_by"}
    for incident in result["incidents"]:
        assert not (forbidden & set(incident))


async def test_the_allowlist_is_pushed_down_as_sysparm_fields(make_service, fake):
    """Unwanted columns are never transferred, not merely dropped on arrival."""
    service = make_service()
    await service.search_incidents(limit=3)

    requested = fake.table_requests[0].param("sysparm_fields")
    assert requested is not None
    assert set(requested.split(",")) == set(INCIDENT_SUMMARY_FIELDS)


async def test_display_values_are_requested_so_references_read_as_labels(
    make_service, fake
):
    service = make_service()
    result = await service.search_incidents(limit=1)

    request = fake.table_requests[0]
    assert request.param("sysparm_display_value") == "true"
    assert request.param("sysparm_exclude_reference_link") == "true"

    incident = result["incidents"][0]
    assert incident["assignment_group"] == "Network Support"
    assert incident["state"] in {"New", "In Progress", "Resolved"}
    assert incident["caller_id"] == "Dana Reyes"


async def test_search_omits_narrative_fields_but_detail_includes_them(make_service):
    service = make_service()
    summary = await service.search_incidents(limit=1, order_by="number")
    assert "description" not in summary["incidents"][0]

    detail = await service.get_incident(number="INC0000001")
    assert "description" in detail["incident"]


async def test_journal_fields_are_off_by_default(make_service, fake):
    service = make_service()

    await service.get_incident(number="INC0000001")
    fields = fake.table_requests[-1].param("sysparm_fields").split(",")
    assert "work_notes" not in fields and "comments" not in fields

    await service.get_incident(number="INC0000001", include_journal=True)
    fields = fake.table_requests[-1].param("sysparm_fields").split(",")
    assert "work_notes" in fields and "comments" in fields


async def test_group_and_ci_projections_are_bounded(make_service):
    service = make_service()

    groups = await service.list_assignment_groups(limit=5)
    for group in groups["groups"]:
        assert set(group) <= set(ASSIGNMENT_GROUP_FIELDS)
        assert "u_internal_notes" not in group

    ci = await service.lookup_ci_owner(identifier="app-prod-04")
    assert set(ci["ci"]) <= set(CMDB_CI_FIELDS)
    # Serial numbers and IPs are outside the allowlist on purpose.
    assert "serial_number" not in ci["ci"]
    assert "ip_address" not in ci["ci"]


async def test_ci_owner_rollup_only_reports_populated_fields(make_service):
    service = make_service()

    full = await service.lookup_ci_owner(identifier="app-prod-04")
    assert full["owners"] == {
        "support_group": "Network Support",
        "managed_by": "Sam Okafor",
        "owned_by": "Priya Nandakumar",
    }

    sparse = await service.lookup_ci_owner(identifier="app-prod-05")
    assert sparse["owners"] == {"support_group": "Database Ops"}


# -- projection unit behaviour ------------------------------------------


def test_unknown_keys_are_discarded_and_missing_keys_are_absent():
    projected = project_record(
        {"number": "INC1", "u_secret": "x"}, INCIDENT_SUMMARY_FIELDS
    )
    assert projected == {"number": "INC1"}


def test_empty_values_are_dropped_by_default():
    record = {"number": "INC1", "category": "", "priority": None}
    assert project_record(record, INCIDENT_SUMMARY_FIELDS) == {"number": "INC1"}
    assert project_record(record, INCIDENT_SUMMARY_FIELDS, drop_empty=False) == {
        "number": "INC1",
        "category": "",
        "priority": "",
    }


@pytest.mark.parametrize(
    "raw,expected",
    [
        ({"display_value": "Network Support", "value": "abc"}, "Network Support"),
        ({"link": "https://x/y", "value": "abc"}, "abc"),
        ({"value": "abc"}, "abc"),
        ({}, ""),
        ("plain", "plain"),
        (None, ""),
    ],
)
def test_reference_shapes_are_normalised_to_a_scalar(raw, expected):
    projected = project_record(
        {"assignment_group": raw}, ("assignment_group",), drop_empty=False
    )
    assert projected["assignment_group"] == expected


def test_long_text_is_truncated_with_a_visible_marker():
    projected = project_record(
        {"description": "x" * 5_000, "short_description": "y" * 1_000},
        INCIDENT_DETAIL_FIELDS,
    )
    assert projected["description"].endswith(TRUNCATION_SUFFIX)
    assert len(projected["description"]) == 2_000 + len(TRUNCATION_SUFFIX)
    assert len(projected["short_description"]) == 300 + len(TRUNCATION_SUFFIX)


def test_short_text_is_left_alone():
    projected = project_record({"description": "brief"}, INCIDENT_DETAIL_FIELDS)
    assert projected["description"] == "brief"


def test_detail_is_a_superset_of_summary():
    assert set(INCIDENT_SUMMARY_FIELDS) < set(INCIDENT_DETAIL_FIELDS)


async def test_projection_measurably_shrinks_the_payload(make_service, fake):
    """The point of the allowlist: fewer bytes into the model's context."""
    import json

    service = make_service()
    result = await service.search_incidents(limit=25)

    projected_bytes = len(json.dumps(result["incidents"]))
    raw_bytes = len(json.dumps(fake.rows("incident"), default=str))
    assert projected_bytes < raw_bytes * 0.5
