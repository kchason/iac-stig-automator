import pytest
from importlib import resources

from stig_automator.plan_parser import walk_resources
from stig_automator.registry import get_module

import stig_automator.modules as stig_modules  # noqa: F401


@pytest.fixture
def rds_mysql_module():
    return get_module("rds_mysql")


@pytest.fixture
def rds_mysql_resources(rds_mysql_plan, rds_mysql_module):
    all_resources = walk_resources(rds_mysql_plan)
    return rds_mysql_module.find_resources(all_resources)


@pytest.fixture
def compliant_resource(rds_mysql_resources):
    for resource, related in rds_mysql_resources:
        if "compliant" in resource.get("address", "") and "non" not in resource.get("address", ""):
            return resource, related
    pytest.fail("Compliant RDS MySQL instance not found in sample plan")


@pytest.fixture
def non_compliant_resource(rds_mysql_resources):
    for resource, related in rds_mysql_resources:
        if "non_compliant" in resource.get("address", ""):
            return resource, related
    pytest.fail("Non-compliant RDS MySQL instance not found in sample plan")


class TestRdsMysqlCompliant:
    @staticmethod
    def _extract_outcome(outcome) -> tuple[bool, str, bool]:
        if len(outcome) == 3:
            met, detail, not_applicable = outcome
            return met, detail, not_applicable
        met, detail = outcome
        return met, detail, False

    @staticmethod
    def _assert_aws_evidence(control_id: str, detail: str) -> None:
        assert "AWS documentation evidence: " in detail, f"{control_id} detail should identify AWS documentation"
        assert detail.count('"') >= 2, f"{control_id} detail should include direct quoted evidence"
        assert "https://docs.aws.amazon.com/AmazonRDS/" in detail

    def test_all_controls_met(self, rds_mysql_module, compliant_resource):
        resource, related = compliant_resource
        for control in rds_mysql_module.controls():
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"
            if not_applicable:
                assert "requires manual review" in detail
                continue
            self._assert_aws_evidence(control.vuln_id, detail)
            assert "https://registry.terraform.io/providers/hashicorp/aws/" in detail

    def test_control_count(self, rds_mysql_module):
        assert len(rds_mysql_module.controls()) == 17

    def test_audit_events_accept_mariadb_plugin_values(self, rds_mysql_module):
        control = next(control for control in rds_mysql_module.controls() if control.vuln_id == "V-235097")
        related = [
            {
                "type": "aws_db_option_group",
                "values": {"option": [{"option_name": "MARIADB_AUDIT_PLUGIN"}]},
            },
            {
                "type": "aws_db_parameter_group",
                "values": {
                    "parameter": [
                        {"name": "server_audit_events", "value": "CONNECT,QUERY_DCL,QUERY_DDL,QUERY_DML"},
                    ],
                },
            },
        ]

        met, detail = control.check({}, related)

        assert met
        assert (
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.MySQL.Options.AuditPlugin.html" in detail
        )
        assert "RDBMS docs: https://mariadb.com/docs/server/reference/plugins/mariadb-audit-plugin" in detail

    def test_audit_events_require_connect_with_query_shortcut(self, rds_mysql_module):
        control = next(control for control in rds_mysql_module.controls() if control.vuln_id == "V-235097")
        related = [
            {
                "type": "aws_db_option_group",
                "values": {"option": [{"option_name": "MARIADB_AUDIT_PLUGIN"}]},
            },
            {
                "type": "aws_db_parameter_group",
                "values": {
                    "parameter": [
                        {"name": "server_audit_events", "value": "QUERY"},
                    ],
                },
            },
        ]

        met, detail = control.check({}, related)

        assert not met
        assert "missing: connect" in detail

    def test_audit_events_allow_query_with_connect(self, rds_mysql_module):
        control = next(control for control in rds_mysql_module.controls() if control.vuln_id == "V-235097")
        related = [
            {
                "type": "aws_db_option_group",
                "values": {"option": [{"option_name": "MARIADB_AUDIT_PLUGIN"}]},
            },
            {
                "type": "aws_db_parameter_group",
                "values": {
                    "parameter": [
                        {"name": "server_audit_events", "value": "CONNECT,QUERY"},
                    ],
                },
            },
        ]

        met, _detail = control.check({}, related)

        assert met

    def test_controls_load_from_json_resource(self, rds_mysql_module):
        with resources.files(stig_modules).joinpath("stigs/rds_mysql_controls.json").open(encoding="utf-8") as f:
            control_data = f.read()

        assert "V-235096" in control_data
        assert len(rds_mysql_module.controls()) == control_data.count('"vuln_id"')

    def test_v235096_uses_concurrent_session_check(self, rds_mysql_module, compliant_resource):
        resource, related = compliant_resource
        control = next(control for control in rds_mysql_module.controls() if control.vuln_id == "V-235096")

        met, detail, not_applicable = self._extract_outcome(control.check(resource, related))

        assert met
        assert not_applicable is False
        assert "max_user_connections" in detail
        assert "require_secure_transport" not in detail

    def test_unverifiable_controls_require_manual_review(self, rds_mysql_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in rds_mysql_module.controls()}
        manual_ids = {"V-235098", "V-235099", "V-235100", "V-235101", "V-235102", "V-235110", "V-235134"}

        for vuln_id in manual_ids:
            met, detail, not_applicable = self._extract_outcome(controls[vuln_id].check(resource, related))
            assert met
            assert not_applicable
            assert "requires manual review" in detail
            assert "no Terraform property fully verifies" in detail
            assert "publicly_accessible" not in detail
            assert "maintenance_window" not in detail


class TestRdsMysqlNonCompliant:
    def test_expected_failures(self, rds_mysql_module, non_compliant_resource):
        resource, related = non_compliant_resource
        failed_ids = set()
        for control in rds_mysql_module.controls():
            outcome = control.check(resource, related)
            met = outcome[0]
            if not met:
                failed_ids.add(control.vuln_id)

        expected_failures = {
            "V-235096",
            "V-235097",
            "V-235111",
            "V-235112",
            "V-235120",
            "V-235121",
            "V-235130",
            "V-235131",
            "V-235132",
            "V-235133",
        }
        assert expected_failures <= failed_ids

    def test_failed_controls_include_remediation_comments(self, rds_mysql_module, non_compliant_resource):
        resource, related = non_compliant_resource
        for control in rds_mysql_module.controls():
            outcome = control.check(resource, related)
            met = outcome[0]
            not_applicable = len(outcome) == 3 and outcome[2]
            if not met and not not_applicable:
                assert "Terraform remediation: configure" in control.remediation_comment
                assert "https://registry.terraform.io/providers/hashicorp/aws/" in control.remediation_comment
                assert "aws_" in control.remediation_comment

    def test_automated_details_include_terraform_properties(self, rds_mysql_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in rds_mysql_module.controls()}

        for vuln_id in {"V-235096", "V-235097", "V-235111"}:
            outcome = controls[vuln_id].check(resource, related)
            detail = outcome[1]
            assert "Terraform properties addressed:" in detail
            assert "aws_db_parameter_group" in detail

    def test_audit_events_accept_unprefixed_aliases(self, rds_mysql_module, compliant_resource):
        resource, related = compliant_resource
        related = [
            {
                **item,
                "values": {
                    **item["values"],
                    "parameter": [
                        {"name": "require_secure_transport", "value": "ON"},
                        {"name": "tls_version", "value": "TLSv1.2,TLSv1.3"},
                        {"name": "max_user_connections", "value": "50"},
                        {"name": "server_audit_events", "value": "CONNECTION,DDL,DCL,DML"},
                    ],
                },
            }
            if item["type"] == "aws_db_parameter_group"
            else item
            for item in related
        ]
        control = next(control for control in rds_mysql_module.controls() if control.vuln_id == "V-235097")

        met, detail = control.check(resource, related)

        assert met
        assert "server_audit_events=CONNECTION,DDL,DCL,DML" in detail
        assert "normalized:" in detail

    def test_audit_events_report_missing_dml_separately_from_aliases(self, rds_mysql_module, compliant_resource):
        resource, related = compliant_resource
        related = [
            {
                **item,
                "values": {
                    **item["values"],
                    "parameter": [
                        {"name": "require_secure_transport", "value": "ON"},
                        {"name": "tls_version", "value": "TLSv1.2,TLSv1.3"},
                        {"name": "max_user_connections", "value": "50"},
                        {"name": "server_audit_events", "value": "CONNECTION,DDL,DCL"},
                    ],
                },
            }
            if item["type"] == "aws_db_parameter_group"
            else item
            for item in related
        ]
        control = next(control for control in rds_mysql_module.controls() if control.vuln_id == "V-235097")

        met, detail = control.check(resource, related)

        assert not met
        assert "missing: query_dml" in detail
        assert "query_dcl" not in detail.split("missing:", 1)[1]
        assert "query_ddl" not in detail.split("missing:", 1)[1]


class TestRdsMysqlResourceDiscovery:
    def test_finds_mysql_instances_and_aurora_cluster(self, rds_mysql_resources):
        assert len(rds_mysql_resources) == 3

    def test_finds_aurora_mysql_cluster(self, rds_mysql_resources):
        cluster_addresses = [resource.get("address", "") for resource, _related in rds_mysql_resources]
        assert "aws_rds_cluster.compliant_aurora_mysql" in cluster_addresses

    def test_aurora_cluster_passes_all_controls(self, rds_mysql_module, rds_mysql_resources):
        for resource, related in rds_mysql_resources:
            if resource.get("address") != "aws_rds_cluster.compliant_aurora_mysql":
                continue
            for control in rds_mysql_module.controls():
                outcome = control.check(resource, related)
                met = outcome[0]
                not_applicable = len(outcome) == 3 and outcome[2]
                assert met or not_applicable, f"{control.vuln_id} failed for Aurora cluster: {outcome[1]}"
            return
        pytest.fail("Aurora MySQL cluster not found in sample plan")

    def test_compliant_resource_has_related_resources(self, compliant_resource):
        _resource, related = compliant_resource
        related_types = {resource["type"] for resource in related}
        assert "aws_db_parameter_group" in related_types
        assert "aws_db_option_group" in related_types
        assert "aws_db_subnet_group" in related_types
