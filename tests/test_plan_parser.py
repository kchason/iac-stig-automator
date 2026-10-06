import json
from pathlib import Path

import pytest

from stig_automator.plan_parser import filter_by_address, filter_by_type, walk_resources

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PLAN_FIXTURES = sorted(FIXTURES_DIR.glob("*_sample_plan.json"))
PLAN_STATE_FIXTURES = [
    (plan_path, plan_path.with_name(plan_path.name.replace("_plan", "_state")))
    for plan_path in PLAN_FIXTURES
]


@pytest.fixture
def planned_values_plan():
    return {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": "a.b", "type": "type_a", "name": "b", "values": {"x": 1}},
                    {"address": "a.c", "type": "type_b", "name": "c", "values": {"x": 2}},
                ],
                "child_modules": [
                    {
                        "resources": [
                            {"address": "module.m.a.d", "type": "type_a", "name": "d", "values": {"x": 3}},
                        ],
                        "child_modules": [],
                    }
                ],
            }
        }
    }


@pytest.fixture
def resource_changes_plan():
    return {
        "resource_changes": [
            {
                "address": "a.e",
                "name": "e",
                "type": "type_a",
                "change": {"after": {"x": 4}},
            }
        ]
    }


@pytest.fixture
def prior_state_plan():
    return {
        "prior_state": {
            "root_module": {
                "resources": [
                    {"address": "a.f", "type": "type_c", "name": "f", "values": {"x": 5}},
                ]
            }
        }
    }


@pytest.fixture
def values_state():
    return {
        "values": {
            "root_module": {
                "resources": [
                    {"address": "a.g", "type": "type_a", "name": "g", "values": {"x": 6}},
                ],
                "child_modules": [
                    {
                        "resources": [
                            {"address": "module.m.a.h", "type": "type_b", "name": "h", "values": {"x": 7}},
                        ],
                    }
                ],
            }
        }
    }


@pytest.fixture
def prior_state_values_plan():
    return {
        "prior_state": {
            "values": {
                "root_module": {
                    "resources": [
                        {"address": "a.i", "type": "type_a", "name": "i", "values": {"x": 8}},
                    ]
                }
            }
        }
    }


@pytest.fixture
def raw_state():
    return {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "module": "module.database",
                "type": "type_a",
                "name": "j",
                "instances": [
                    {"index_key": "primary", "attributes": {"x": 9}},
                ],
            },
            {
                "mode": "data",
                "type": "type_a",
                "name": "ignored",
                "instances": [
                    {"attributes": {"x": 10}},
                ],
            },
        ],
    }


class TestWalkResources:
    def test_planned_values(self, planned_values_plan):
        resources = walk_resources(planned_values_plan)
        assert len(resources) == 3
        addresses = {r["address"] for r in resources}
        assert "a.b" in addresses
        assert "module.m.a.d" in addresses

    def test_resource_changes_fallback(self, resource_changes_plan):
        resources = walk_resources(resource_changes_plan)
        assert len(resources) == 1
        assert resources[0]["values"]["x"] == 4

    def test_prior_state(self, prior_state_plan):
        resources = walk_resources(prior_state_plan)
        assert len(resources) == 1
        assert resources[0]["type"] == "type_c"

    def test_values_state(self, values_state):
        resources = walk_resources(values_state)
        assert len(resources) == 2
        addresses = {r["address"] for r in resources}
        assert "a.g" in addresses
        assert "module.m.a.h" in addresses

    def test_prior_state_values(self, prior_state_values_plan):
        resources = walk_resources(prior_state_values_plan)
        assert len(resources) == 1
        assert resources[0]["address"] == "a.i"

    def test_raw_state(self, raw_state):
        resources = walk_resources(raw_state)
        assert len(resources) == 1
        assert resources[0]["address"] == 'module.database.type_a.j["primary"]'
        assert resources[0]["values"]["x"] == 9

    @pytest.mark.parametrize(
        "plan_path,state_path",
        PLAN_STATE_FIXTURES,
        ids=[plan_path.name for plan_path, _state_path in PLAN_STATE_FIXTURES],
    )
    def test_state_values_match_plan_fixture_resources(self, plan_path, state_path):
        plan = json.loads(plan_path.read_text())
        state = json.loads(state_path.read_text())

        assert walk_resources(state) == walk_resources(plan)

    def test_empty_plan(self):
        assert walk_resources({}) == []


class TestFilterByType:
    def test_filter(self, planned_values_plan):
        resources = walk_resources(planned_values_plan)
        filtered = filter_by_type(resources, "type_a")
        assert len(filtered) == 2

    def test_no_match(self, planned_values_plan):
        resources = walk_resources(planned_values_plan)
        assert filter_by_type(resources, "nonexistent") == []


class TestFilterByAddress:
    def test_glob_match(self, planned_values_plan):
        resources = walk_resources(planned_values_plan)
        filtered = filter_by_address(resources, ["module.*"])
        assert len(filtered) == 1
        assert filtered[0]["address"] == "module.m.a.d"

    def test_exact_match(self, planned_values_plan):
        resources = walk_resources(planned_values_plan)
        filtered = filter_by_address(resources, ["a.b"])
        assert len(filtered) == 1

    def test_no_match(self, planned_values_plan):
        resources = walk_resources(planned_values_plan)
        assert filter_by_address(resources, ["zzz*"]) == []

    def test_multiple_patterns(self, planned_values_plan):
        resources = walk_resources(planned_values_plan)
        filtered = filter_by_address(resources, ["a.b", "a.c"])
        assert len(filtered) == 2
