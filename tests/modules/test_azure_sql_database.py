import pytest
from importlib import resources

from stig_automator.plan_parser import walk_resources
from stig_automator.registry import get_module

import stig_automator.modules as stig_modules  # noqa: F401


@pytest.fixture
def azure_sql_database_module():
    return get_module("azure_sql_database")


@pytest.fixture
def azure_sql_database_resources(azure_sql_database_plan, azure_sql_database_module):
    all_resources = walk_resources(azure_sql_database_plan)
    return azure_sql_database_module.find_resources(all_resources)


@pytest.fixture
def compliant_resource(azure_sql_database_resources):
    for resource, related in azure_sql_database_resources:
        if "compliant" in resource.get("address", "") and "non" not in resource.get("address", ""):
            return resource, related
    pytest.fail("Compliant Azure SQL server not found in sample plan")


@pytest.fixture
def non_compliant_resource(azure_sql_database_resources):
    for resource, related in azure_sql_database_resources:
        if "non_compliant" in resource.get("address", ""):
            return resource, related
    pytest.fail("Non-compliant Azure SQL server not found in sample plan")


VALIDATION_CONTROL_IDS = {
    "V-255301",
    "V-255320",
    "V-255321",
    "V-255322",
    "V-255334",
    "V-255336",
    "V-255339",
    "V-255345",
    "V-255346",
    "V-255347",
    "V-255348",
    "V-255349",
    "V-255370",
    "V-255371",
    "V-255372",
    "V-255377",
}


class TestAzureSqlDatabaseCompliant:
    def test_validation_controls_met(self, azure_sql_database_module, compliant_resource):
        resource, related = compliant_resource
        for control in azure_sql_database_module.controls():
            if control.vuln_id not in VALIDATION_CONTROL_IDS:
                continue
            met, detail = control.check(resource, related)
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"
            assert "Microsoft Learn evidence:" in detail

    def test_control_count(self, azure_sql_database_module):
        assert len(azure_sql_database_module.controls()) == 76

    def test_controls_load_from_json_resource(self, azure_sql_database_module):
        with resources.files(stig_modules).joinpath(
            "stigs/azure_sql_database_controls.json",
        ).open(encoding="utf-8") as handle:
            control_data = handle.read()

        assert "V-255301" in control_data
        assert len(azure_sql_database_module.controls()) == control_data.count('"vuln_id"')


class TestAzureSqlDatabaseNonCompliant:
    def test_validation_controls_fail(self, azure_sql_database_module, non_compliant_resource):
        resource, related = non_compliant_resource
        failed_ids = set()
        for control in azure_sql_database_module.controls():
            if control.vuln_id not in VALIDATION_CONTROL_IDS:
                continue
            met, _detail = control.check(resource, related)
            if not met:
                failed_ids.add(control.vuln_id)

        assert VALIDATION_CONTROL_IDS <= failed_ids


class TestAzureSqlDatabaseResourceDiscovery:
    def test_finds_both_servers(self, azure_sql_database_resources):
        assert len(azure_sql_database_resources) == 2

    def test_compliant_resource_has_related_resources(self, compliant_resource):
        _resource, related = compliant_resource
        related_types = {resource["type"] for resource in related}
        assert "azurerm_mssql_database" in related_types
        assert "azurerm_mssql_server_extended_auditing_policy" in related_types
        assert "azurerm_monitor_diagnostic_setting" in related_types
