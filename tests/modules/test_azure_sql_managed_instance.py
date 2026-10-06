import pytest
from importlib import resources

from stig_automator.plan_parser import walk_resources
from stig_automator.registry import get_module

import stig_automator.modules as stig_modules  # noqa: F401


@pytest.fixture
def azure_sql_managed_instance_module():
    return get_module("azure_sql_managed_instance")


@pytest.fixture
def azure_sql_managed_instance_resources(azure_sql_managed_instance_plan, azure_sql_managed_instance_module):
    all_resources = walk_resources(azure_sql_managed_instance_plan)
    return azure_sql_managed_instance_module.find_resources(all_resources)


@pytest.fixture
def compliant_resource(azure_sql_managed_instance_resources):
    for resource, related in azure_sql_managed_instance_resources:
        if "compliant" in resource.get("address", "") and "non" not in resource.get("address", ""):
            return resource, related
    pytest.fail("Compliant Azure SQL managed instance not found in sample plan")


@pytest.fixture
def non_compliant_resource(azure_sql_managed_instance_resources):
    for resource, related in azure_sql_managed_instance_resources:
        if "non_compliant" in resource.get("address", ""):
            return resource, related
    pytest.fail("Non-compliant Azure SQL managed instance not found in sample plan")


VALIDATION_CONTROL_IDS = {
    "V-276225",
    "V-276236",
    "V-276237",
    "V-276238",
    "V-276246",
    "V-276248",
    "V-276251",
    "V-276260",
    "V-276261",
    "V-276262",
    "V-276265",
    "V-276267",
    "V-276295",
    "V-276305",
    "V-276310",
}


class TestAzureSqlManagedInstanceCompliant:
    def test_validation_controls_met(self, azure_sql_managed_instance_module, compliant_resource):
        resource, related = compliant_resource
        for control in azure_sql_managed_instance_module.controls():
            if control.vuln_id not in VALIDATION_CONTROL_IDS:
                continue
            met, detail = control.check(resource, related)
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"
            assert "Microsoft Learn evidence:" in detail

    def test_control_count(self, azure_sql_managed_instance_module):
        assert len(azure_sql_managed_instance_module.controls()) == 84

    def test_controls_load_from_json_resource(self, azure_sql_managed_instance_module):
        with resources.files(stig_modules).joinpath(
            "stigs/azure_sql_managed_instance_controls.json",
        ).open(encoding="utf-8") as handle:
            control_data = handle.read()

        assert "V-276225" in control_data
        assert len(azure_sql_managed_instance_module.controls()) == control_data.count('"vuln_id"')


class TestAzureSqlManagedInstanceNonCompliant:
    def test_validation_controls_fail(self, azure_sql_managed_instance_module, non_compliant_resource):
        resource, related = non_compliant_resource
        failed_ids = set()
        for control in azure_sql_managed_instance_module.controls():
            if control.vuln_id not in VALIDATION_CONTROL_IDS:
                continue
            met, _detail = control.check(resource, related)
            if not met:
                failed_ids.add(control.vuln_id)

        expected_failures = {
            "V-276225",
            "V-276246",
            "V-276248",
            "V-276260",
            "V-276261",
            "V-276262",
            "V-276265",
            "V-276267",
            "V-276295",
            "V-276305",
            "V-276310",
        }
        assert expected_failures <= failed_ids


class TestAzureSqlManagedInstanceResourceDiscovery:
    def test_finds_both_instances(self, azure_sql_managed_instance_resources):
        assert len(azure_sql_managed_instance_resources) == 2

    def test_compliant_resource_has_related_resources(self, compliant_resource):
        _resource, related = compliant_resource
        related_types = {resource["type"] for resource in related}
        assert "azurerm_mssql_managed_instance_active_directory_administrator" in related_types
        assert "azurerm_mssql_managed_instance_extended_auditing_policy" in related_types
        assert "azurerm_monitor_diagnostic_setting" in related_types
