import pytest
from importlib import resources

from stig_automator.plan_parser import walk_resources
from stig_automator.registry import get_module

import stig_automator.modules as stig_modules  # noqa: F401


INHERITED_CONTROL_IDS = {
    "V-261873",
    "V-261874",
    "V-261875",
    "V-261876",
    "V-261877",
    "V-261878",
    "V-261879",
    "V-261880",
    "V-261882",
    "V-261883",
    "V-261887",
    "V-261888",
    "V-261893",
    "V-261894",
    "V-261896",
    "V-261904",
    "V-261918",
    "V-261935",
    "V-261965",
    "V-261966",
}
MANUAL_CONTROL_IDS = {
    "V-261862",
    "V-261872",
    "V-261881",
    "V-261884",
    "V-261885",
    "V-261886",
    "V-261895",
    "V-261898",
    "V-261902",
    "V-261903",
    "V-261905",
    "V-261906",
    "V-261907",
    "V-261911",
    "V-261912",
    "V-261913",
    "V-261914",
    "V-261915",
    "V-261916",
    "V-261919",
    "V-261920",
    "V-261923",
    "V-261924",
    "V-261927",
    "V-261928",
    "V-261934",
}


@pytest.fixture
def postgres_module():
    return get_module("postgres_flexible")


@pytest.fixture
def postgres_resources(postgres_plan, postgres_module):
    all_res = walk_resources(postgres_plan)
    return postgres_module.find_resources(all_res)


@pytest.fixture
def compliant_resource(postgres_resources):
    for res, related in postgres_resources:
        if "compliant" in res.get("address", "") and "non" not in res.get("address", ""):
            return res, related
    pytest.fail("Compliant server not found in sample plan")


@pytest.fixture
def non_compliant_resource(postgres_resources):
    for res, related in postgres_resources:
        if "non_compliant" in res.get("address", ""):
            return res, related
    pytest.fail("Non-compliant server not found in sample plan")


def _extract_outcome(outcome) -> tuple[bool, str, bool]:
    if len(outcome) == 3:
        met, detail, not_applicable = outcome
        return met, detail, not_applicable
    met, detail = outcome
    return met, detail, False


class TestPostgresCompliant:
    @staticmethod
    def _assert_microsoft_learn_evidence(control_id: str, detail: str) -> None:
        assert "Microsoft Learn evidence: " in detail, f"{control_id} detail should identify Microsoft Learn evidence"
        assert detail.count('"') >= 2, f"{control_id} detail should include direct quoted evidence"
        assert "https://learn.microsoft.com/en-us/azure/postgresql/" in detail, (
            f"{control_id} detail should include Azure documentation links"
        )

    def test_all_controls_met(self, postgres_module, compliant_resource):
        resource, related = compliant_resource
        controls = postgres_module.controls()
        for control in controls:
            met, detail, _not_applicable = _extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"

    def test_all_met_controls_include_quotes_and_links(self, postgres_module, compliant_resource):
        resource, related = compliant_resource
        controls = postgres_module.controls()
        for control in controls:
            met, detail, not_applicable = _extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"
            if not_applicable:
                assert "requires manual review" in detail or "not applicable for unclassified" in detail
                continue
            if control.csp_inherited:
                assert "Inherited CSP/baseline controls:" in detail
                continue
            self._assert_microsoft_learn_evidence(control.vuln_id, detail)
            assert "Terraform properties addressed:" in detail
            assert "https://registry.terraform.io/providers/hashicorp/azurerm/" in detail, (
                f"{control.vuln_id} detail should include Terraform provider documentation"
            )

    def test_control_count(self, postgres_module):
        assert len(postgres_module.controls()) == 111

    def test_pgaudit_detail_includes_rdbms_reference(self, postgres_module, compliant_resource):
        resource, related = compliant_resource
        control = next(control for control in postgres_module.controls() if control.vuln_id == "V-261861")

        met, detail = control.check(resource, related)

        assert met
        assert "RDBMS docs: https://github.com/pgaudit/pgaudit#settings" in detail

    def test_log_prefix_detail_includes_postgresql_reference(self, postgres_module, compliant_resource):
        resource, related = compliant_resource
        control = next(control for control in postgres_module.controls() if control.vuln_id == "V-261871")

        met, detail = control.check(resource, related)

        assert met
        assert "RDBMS docs: https://www.postgresql.org/docs/current/runtime-config-logging.html" in detail

    def test_controls_load_from_json_resource(self, postgres_module):
        with resources.files(stig_modules).joinpath("stigs/postgres_flexible_controls.json").open(
            encoding="utf-8",
        ) as f:
            control_data = f.read()

        assert "V-283674" in control_data
        assert len(postgres_module.controls()) == control_data.count('"vuln_id"')

    def test_session_timeout_and_client_messages(self, postgres_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in postgres_module.controls()}
        for vuln_id in {"V-261868", "V-261869", "V-261870", "V-261908", "V-261910"}:
            met, detail, not_applicable = _extract_outcome(controls[vuln_id].check(resource, related))
            assert met
            assert not not_applicable
            assert "Microsoft Learn evidence:" in detail

    def test_inherited_controls_are_csp_baseline(self, postgres_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in postgres_module.controls()}
        for vuln_id in INHERITED_CONTROL_IDS:
            control = controls[vuln_id]
            met, detail, not_applicable = _extract_outcome(control.check(resource, related))
            assert control.csp_inherited
            assert met
            assert not not_applicable
            assert "Inherited CSP/baseline controls:" in detail

    def test_unverifiable_controls_require_manual_review(self, postgres_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in postgres_module.controls()}
        for vuln_id in MANUAL_CONTROL_IDS:
            met, detail, not_applicable = _extract_outcome(controls[vuln_id].check(resource, related))
            assert met
            assert not_applicable
            if vuln_id == "V-261928":
                assert "not applicable for unclassified" in detail
            else:
                assert "requires manual review" in detail
                assert "no Terraform property fully verifies" in detail


class TestPostgresNonCompliant:
    def test_expected_failures(self, postgres_module, non_compliant_resource):
        resource, related = non_compliant_resource
        controls = postgres_module.controls()
        failed_ids = set()
        for control in controls:
            met, _detail, not_applicable = _extract_outcome(control.check(resource, related))
            if not met and not not_applicable:
                failed_ids.add(control.vuln_id)

        expected_failures = {
            "V-261858",
            "V-261859",
            "V-261891",
            "V-261892",
            "V-261901",
            "V-261857",
            "V-261861",
            "V-261865",
            "V-261866",
            "V-261867",
            "V-261868",
            "V-261869",
            "V-261870",
            "V-261871",
            "V-261889",
            "V-261899",
            "V-261908",
            "V-261910",
            "V-261917",
            "V-261921",
            "V-261922",
            "V-261929",
        }
        assert expected_failures <= failed_ids

    def test_failed_controls_include_remediation_comments(self, postgres_module, non_compliant_resource):
        resource, related = non_compliant_resource
        for control in postgres_module.controls():
            met, _detail, not_applicable = _extract_outcome(control.check(resource, related))
            if not met and not not_applicable:
                assert "Terraform remediation: configure" in control.remediation_comment
                assert "https://registry.terraform.io/providers/hashicorp/azurerm/" in control.remediation_comment
                assert "azurerm_" in control.remediation_comment


class TestPostgresVersionChecks:
    @staticmethod
    def _server_with_version(compliant_resource, version: str) -> tuple[dict, list]:
        resource, related = compliant_resource
        server = dict(resource)
        values = dict(server.get("values", {}))
        values["version"] = version
        server["values"] = values
        return server, related

    def test_version_14_meets_vendor_support_and_managed_updates(self, postgres_module, compliant_resource):
        resource, related = self._server_with_version(compliant_resource, "14")
        controls = {control.vuln_id: control for control in postgres_module.controls()}
        for vuln_id in ("V-283674", "V-261936"):
            met, detail, not_applicable = _extract_outcome(controls[vuln_id].check(resource, related))
            assert met, f"{vuln_id} failed: {detail}"
            assert not not_applicable
            assert "Microsoft Learn evidence:" in detail

    def test_unsupported_major_fails_vendor_support_and_managed_updates(self, postgres_module, compliant_resource):
        resource, related = self._server_with_version(compliant_resource, "9")
        controls = {control.vuln_id: control for control in postgres_module.controls()}
        met_283674, detail_283674, _ = _extract_outcome(controls["V-283674"].check(resource, related))
        met_261936, detail_261936, _ = _extract_outcome(controls["V-261936"].check(resource, related))
        assert not met_283674
        assert not met_261936
        assert "Azure-supported" in detail_283674
        assert "security updates require" in detail_261936
        assert detail_283674 != detail_261936

    def test_managed_updates_detail_cites_maintenance(self, postgres_module, compliant_resource):
        resource, related = self._server_with_version(compliant_resource, "14")
        control = next(c for c in postgres_module.controls() if c.vuln_id == "V-261936")
        met, detail, _ = _extract_outcome(control.check(resource, related))
        assert met
        assert "platform maintenance" in detail
        assert "concepts-maintenance" in detail


class TestPostgresResourceDiscovery:
    def test_finds_both_resources(self, postgres_resources):
        assert len(postgres_resources) == 2

    def test_compliant_resource_has_related_resources(self, compliant_resource):
        _resource, related = compliant_resource
        related_types = {resource["type"] for resource in related}
        assert "azurerm_postgresql_flexible_server_configuration" in related_types
        assert "azurerm_monitor_diagnostic_setting" in related_types

    def test_non_compliant_resource_has_firewall_rule(self, non_compliant_resource):
        _resource, related = non_compliant_resource
        addresses = {resource["address"] for resource in related}
        assert "azurerm_postgresql_flexible_server_firewall_rule.non_compliant_open" in addresses
