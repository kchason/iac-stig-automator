import pytest
from importlib import resources

from stig_automator.plan_parser import walk_resources
from stig_automator.registry import get_module

import stig_automator.modules as stig_modules  # noqa: F401


@pytest.fixture
def mysql_module():
    return get_module("mysql_flexible")


@pytest.fixture
def mysql_resources(mysql_plan, mysql_module):
    all_res = walk_resources(mysql_plan)
    return mysql_module.find_resources(all_res)


@pytest.fixture
def compliant_resource(mysql_resources):
    for res, related in mysql_resources:
        if "compliant" in res.get("address", "") and "non" not in res.get("address", ""):
            return res, related
    pytest.fail("Compliant server not found in sample plan")


@pytest.fixture
def non_compliant_resource(mysql_resources):
    for res, related in mysql_resources:
        if "non_compliant" in res.get("address", ""):
            return res, related
    pytest.fail("Non-compliant server not found in sample plan")


class TestMysqlCompliant:
    @staticmethod
    def _extract_outcome(outcome) -> tuple[bool, str, bool]:
        if len(outcome) == 3:
            met, detail, not_applicable = outcome
            return met, detail, not_applicable
        met, detail = outcome
        return met, detail, False

    @staticmethod
    def _assert_microsoft_learn_evidence(control_id: str, detail: str) -> None:
        assert "Microsoft Learn evidence: " in detail, f"{control_id} detail should identify Microsoft Learn evidence"
        assert detail.count('"') >= 2, f"{control_id} detail should include direct quoted evidence"
        assert "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/" in detail, (
            f"{control_id} detail should include Azure documentation links"
        )

    def test_all_controls_met(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        controls = mysql_module.controls()
        for control in controls:
            met, detail, _not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"

    def test_all_met_controls_include_quotes_and_links(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        controls = mysql_module.controls()
        for control in controls:
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"
            if not_applicable:
                assert "requires manual review" in detail
                continue
            if control.csp_inherited:
                assert "Inherited CSP/baseline controls:" in detail
                continue
            self._assert_microsoft_learn_evidence(control.vuln_id, detail)
            assert "https://registry.terraform.io/providers/hashicorp/azurerm/" in detail, (
                f"{control.vuln_id} detail should include Terraform provider documentation"
            )

    def test_control_count(self, mysql_module):
        assert len(mysql_module.controls()) == 17

    def test_audit_events_use_azure_event_classes(self, mysql_module):
        control = next(control for control in mysql_module.controls() if control.vuln_id == "V-235097")
        resource = {"values": {"audit_log_enabled": "ON", "audit_log_events": "CONNECTION,DCL,DDL,DML"}}

        met, detail = control.check(resource, [])

        assert met
        assert "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-monitor-mysql" in detail
        assert "RDBMS docs: https://dev.mysql.com/doc/refman/8.0/en/grant.html" in detail

    def test_audit_events_reject_rds_mariadb_event_classes(self, mysql_module):
        control = next(control for control in mysql_module.controls() if control.vuln_id == "V-235097")
        resource = {"values": {"audit_log_enabled": "ON", "audit_log_events": "CONNECTION,QUERY_DCL,QUERY_DDL"}}

        met, detail = control.check(resource, [])

        assert not met
        assert "missing recommended event types: DCL, DDL, DML" in detail

    def test_audit_events_allow_general_with_connection_v2(self, mysql_module):
        control = next(control for control in mysql_module.controls() if control.vuln_id == "V-235097")
        resource = {"values": {"audit_log_enabled": "ON", "audit_log_events": "CONNECTION_V2,GENERAL"}}

        met, _detail = control.check(resource, [])

        assert met

    def test_controls_load_from_json_resource(self, mysql_module):
        with resources.files(stig_modules).joinpath("stigs/mysql_flexible_controls.json").open(
            encoding="utf-8",
        ) as f:
            control_data = f.read()

        assert "V-235096" in control_data
        assert len(mysql_module.controls()) == control_data.count('"vuln_id"')

    def test_v235096_uses_concurrent_session_check(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        control = next(control for control in mysql_module.controls() if control.vuln_id == "V-235096")

        met, detail, not_applicable = self._extract_outcome(control.check(resource, related))

        assert met
        assert not_applicable is False
        assert "max_user_connections" in detail
        assert "require_secure_transport" not in detail

    def test_unverifiable_controls_require_manual_review(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in mysql_module.controls()}
        manual_ids = {"V-235098", "V-235102", "V-235110", "V-235134"}

        for vuln_id in manual_ids:
            met, detail, not_applicable = self._extract_outcome(controls[vuln_id].check(resource, related))
            assert met
            assert not_applicable
            assert "requires manual review" in detail
            assert "no Terraform property fully verifies" in detail
            assert "public_network_access" not in detail
            assert "maintenance_window" not in detail

    def test_audit_log_storage_controls_are_azure_inherited(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in mysql_module.controls()}

        for vuln_id in {"V-235099", "V-235100", "V-235101"}:
            control = controls[vuln_id]
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert control.csp_inherited
            assert met
            assert not not_applicable
            assert "manual review" not in detail
            assert "Azure Monitor diagnostic settings" in detail
            assert "Inherited CSP/baseline controls:" in detail
            self._assert_microsoft_learn_evidence(vuln_id, detail)


class TestMysqlNonCompliant:
    def test_expected_failures(self, mysql_module, non_compliant_resource):
        resource, related = non_compliant_resource
        controls = mysql_module.controls()
        failed_ids = set()
        for control in controls:
            outcome = control.check(resource, related)
            met = outcome[0]
            if not met:
                failed_ids.add(control.vuln_id)

        expected_failures = {
            "V-235096",  # Concurrent session limit
            "V-235097",  # Audit event coverage
            "V-235111",  # Audit privilege additions
            "V-235112",  # Audit failed privilege additions
            "V-235120",  # Audit failed privilege deletions
            "V-235121",  # Audit security object deletions
            "V-235130",  # Audit concurrent logons
            "V-235131",  # Audit successful object access
            "V-235132",  # Audit unsuccessful object access
            "V-235133",  # Audit direct database access
        }
        for vuln_id in expected_failures:
            assert vuln_id in failed_ids, f"{vuln_id} should have failed but passed"

    def test_failed_controls_include_remediation_comments(self, mysql_module, non_compliant_resource):
        resource, related = non_compliant_resource
        for control in mysql_module.controls():
            outcome = control.check(resource, related)
            met = outcome[0]
            not_applicable = len(outcome) == 3 and outcome[2]
            if not met and not not_applicable:
                assert "Terraform remediation: configure" in control.remediation_comment
                assert "https://registry.terraform.io/providers/hashicorp/azurerm/" in control.remediation_comment
                assert "azurerm_" in control.remediation_comment

    def test_automated_details_include_terraform_properties(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in mysql_module.controls()}

        for vuln_id in {"V-235096", "V-235097", "V-235111"}:
            outcome = controls[vuln_id].check(resource, related)
            detail = outcome[1]
            assert "Terraform properties addressed:" in detail
            assert "azurerm_mysql_flexible_server" in detail

    def test_audit_events_accept_unprefixed_mysql_values(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        control = next(control for control in mysql_module.controls() if control.vuln_id == "V-235097")

        met, detail = control.check(resource, related)

        assert met
        assert "audit_log_events=CONNECTION,DCL,DDL,DML" in detail
        assert "normalized:" in detail

    def test_audit_events_report_missing_dml_separately_from_prefixes(self, mysql_module, compliant_resource):
        resource, related = compliant_resource
        resource = {
            **resource,
            "values": {
                **resource["values"],
                "audit_log_events": "CONNECTION,DDL,DCL",
            },
        }
        control = next(control for control in mysql_module.controls() if control.vuln_id == "V-235097")

        met, detail = control.check(resource, related)

        assert not met
        assert "missing recommended event types: DML" in detail
        assert "QUERY_DCL" not in detail
        assert "QUERY_DDL" not in detail


class TestMysqlResourceDiscovery:
    def test_finds_both_resources(self, mysql_resources):
        assert len(mysql_resources) == 2

    def test_resource_has_expected_keys(self, mysql_resources):
        for res, related in mysql_resources:
            assert "address" in res
            assert "type" in res
            assert "values" in res
