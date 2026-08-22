"""Tests for the fake instance itself.

The fake is load-bearing: every other test's assertions are only as good as its
fidelity to the Table API. These tests pin the semantics it claims to honour.
"""

from __future__ import annotations

import httpx
import pytest

from .fake_servicenow import FakeServiceNow, Ref, make_groups, make_incidents


@pytest.fixture
def raw() -> FakeServiceNow:
    return FakeServiceNow(
        tables={"incident": make_incidents(10), "sys_user_group": make_groups()},
        username="u",
        password="p",
    )


async def get(fake: FakeServiceNow, path: str, **params) -> httpx.Response:
    async with httpx.AsyncClient(transport=fake.transport()) as client:
        return await client.get(
            f"{fake.base_url}{path}", params=params, auth=("u", "p")
        )


async def test_offset_and_limit_slice_the_result_set(raw):
    response = await get(
        raw, "/api/now/table/incident", sysparm_limit=3, sysparm_offset=4,
        sysparm_fields="number",
    )
    assert [r["number"] for r in response.json()["result"]] == [
        "INC0000005",
        "INC0000006",
        "INC0000007",
    ]


async def test_total_count_header_reports_matches_not_page_size(raw):
    response = await get(raw, "/api/now/table/incident", sysparm_limit=2)
    assert response.headers["X-Total-Count"] == "10"


async def test_link_header_advertises_the_next_offset(raw):
    response = await get(raw, "/api/now/table/incident", sysparm_limit=4)
    assert 'rel="next"' in response.headers["Link"]
    assert "sysparm_offset=4" in response.headers["Link"]

    last = await get(raw, "/api/now/table/incident", sysparm_limit=4, sysparm_offset=8)
    assert "Link" not in last.headers


async def test_sysparm_fields_projects_and_pads_missing_columns(raw):
    response = await get(
        raw, "/api/now/table/incident", sysparm_limit=1,
        sysparm_fields="number,not_a_real_column",
    )
    record = response.json()["result"][0]
    assert set(record) == {"number", "not_a_real_column"}
    assert record["not_a_real_column"] == ""


async def test_display_value_modes(raw):
    plain = await get(
        raw, "/api/now/table/incident", sysparm_limit=1, sysparm_fields="state"
    )
    assert plain.json()["result"][0]["state"] == {
        "link": "https://example.service-now.com/api/now/table/x/2",
        "value": "2",
    }

    no_link = await get(
        raw, "/api/now/table/incident", sysparm_limit=1, sysparm_fields="state",
        sysparm_exclude_reference_link="true",
    )
    assert no_link.json()["result"][0]["state"] == "2"

    display = await get(
        raw, "/api/now/table/incident", sysparm_limit=1, sysparm_fields="state",
        sysparm_display_value="true",
    )
    assert display.json()["result"][0]["state"] == "In Progress"

    both = await get(
        raw, "/api/now/table/incident", sysparm_limit=1, sysparm_fields="state",
        sysparm_display_value="all",
    )
    assert both.json()["result"][0]["state"] == {
        "display_value": "In Progress",
        "value": "2",
    }


@pytest.mark.parametrize(
    "query,expected",
    [
        ("state=1", 3),
        ("state!=1", 7),
        ("stateIN1,6", 6),
        ("short_descriptionLIKEtunnel", 10),
        ("short_descriptionLIKEnothing", 0),
        ("numberSTARTSWITHINC000000", 9),
        ("category=network^state=1", 3),
        ("state=1^ORstate=6", 6),
        ("close_codeISEMPTY", 10),
        ("numberISNOTEMPTY", 10),
        ("assignment_group.name=Network Support", 10),
        ("assignment_group.name=Database Ops", 0),
    ],
)
async def test_encoded_query_operators(raw, query, expected):
    response = await get(
        raw, "/api/now/table/incident", sysparm_query=query, sysparm_limit=100
    )
    assert len(response.json()["result"]) == expected


async def test_orderby_ascending_and_descending(raw):
    ascending = await get(
        raw, "/api/now/table/incident", sysparm_query="ORDERBYnumber",
        sysparm_fields="number", sysparm_limit=100,
    )
    numbers = [r["number"] for r in ascending.json()["result"]]
    assert numbers == sorted(numbers)

    descending = await get(
        raw, "/api/now/table/incident", sysparm_query="ORDERBYDESCnumber",
        sysparm_fields="number", sysparm_limit=100,
    )
    assert [r["number"] for r in descending.json()["result"]] == sorted(
        numbers, reverse=True
    )


async def test_numeric_sort_is_numeric_not_lexical():
    fake = FakeServiceNow(
        tables={
            "incident": [
                {"sys_id": "a", "number": "A", "priority": "10"},
                {"sys_id": "b", "number": "B", "priority": "9"},
                {"sys_id": "c", "number": "C", "priority": "2"},
            ]
        },
        require_auth=False,
    )
    response = await get(
        fake, "/api/now/table/incident", sysparm_query="ORDERBYpriority",
        sysparm_fields="number",
    )
    assert [r["number"] for r in response.json()["result"]] == ["C", "B", "A"]


async def test_get_by_sys_id_returns_an_object_not_a_list(raw):
    response = await get(raw, "/api/now/table/incident/inc-sys-0003")
    assert isinstance(response.json()["result"], dict)

    missing = await get(raw, "/api/now/table/incident/nope")
    assert missing.status_code == 404
    assert missing.json()["error"]["message"] == "No Record found"


async def test_auth_is_enforced(raw):
    async with httpx.AsyncClient(transport=raw.transport()) as client:
        anonymous = await client.get(f"{raw.base_url}/api/now/table/incident")
        wrong = await client.get(
            f"{raw.base_url}/api/now/table/incident", auth=("u", "bad")
        )
    assert anonymous.status_code == 401
    assert wrong.status_code == 401


async def test_oauth_token_endpoint():
    fake = FakeServiceNow(client_id="cid", client_secret="csec")
    async with httpx.AsyncClient(transport=fake.transport()) as client:
        good = await client.post(
            f"{fake.base_url}/oauth_token.do",
            data={
                "grant_type": "client_credentials",
                "client_id": "cid",
                "client_secret": "csec",
            },
        )
        bad = await client.post(
            f"{fake.base_url}/oauth_token.do",
            data={
                "grant_type": "client_credentials",
                "client_id": "cid",
                "client_secret": "wrong",
            },
        )
    assert good.json()["access_token"] == "fake-access-token"
    assert bad.status_code == 401


async def test_faults_are_consumed_in_order(raw):
    raw.fail_next(2, status=429, retry_after="5")
    first = await get(raw, "/api/now/table/incident")
    second = await get(raw, "/api/now/table/incident")
    third = await get(raw, "/api/now/table/incident")

    assert first.status_code == 429
    assert first.headers["Retry-After"] == "5"
    assert second.status_code == 429
    assert third.status_code == 200


async def test_writes_store_references_and_append_journals():
    fake = FakeServiceNow(
        tables={"incident": [], "sys_user_group": make_groups(["Network Support"])},
        require_auth=False,
    )
    async with httpx.AsyncClient(transport=fake.transport()) as client:
        created = await client.post(
            f"{fake.base_url}/api/now/table/incident",
            json={"short_description": "x", "assignment_group": "grp-network"},
            params={"sysparm_display_value": "true"},
        )
        assert created.status_code == 201
        assert created.json()["result"]["assignment_group"] == "Network Support"

        sys_id = fake.rows("incident")[0]["sys_id"]
        await client.patch(
            f"{fake.base_url}/api/now/table/incident/{sys_id}",
            json={"work_notes": "first"},
        )
        await client.patch(
            f"{fake.base_url}/api/now/table/incident/{sys_id}",
            json={"work_notes": "second"},
        )

    assert fake.rows("incident")[0]["work_notes"] == "first\nsecond"


async def test_ref_helpers():
    ref = Ref("2", "In Progress")
    assert (ref.value, ref.display_value) == ("2", "In Progress")


async def test_unknown_route_is_a_404(raw):
    response = await get(raw, "/api/now/stats/incident")
    assert response.status_code == 404
