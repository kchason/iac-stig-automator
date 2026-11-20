import pytest
from importlib import resources

from stig_automator.plan_parser import walk_resources
from stig_automator.registry import get_module

import stig_automator.modules as stig_modules  # noqa: F401


EXPECTED_FAILURES = {
    "V-279334",
    "V-279346",
    "V-279350",
    "V-279354",
    "V-279358",
    "V-279361",
    "V-279382",
    "V-279387",
    "V-279389",
    "V-279393",
    "V-279394",
    "V-279412",
    "V-282943",
}


@pytest.fixture
def documentdb_module():
    return get_module("documentdb")


@pytest.fixture
def documentdb_resources(documentdb_plan, documentdb_module):
    return documentdb_module.find_resources(walk_resources(documentdb_plan))


@pytest.fixture
def compliant_resource(documentdb_resources):
    for resource, related in documentdb_resources:
        if resource.get("address") == "aws_docdb_cluster.compliant":
            return resource, related
    pytest.fail("Compliant DocumentDB cluster not found in sample plan")


@pytest.fixture
def non_compliant_resource(documentdb_resources):
    for resource, related in documentdb_resources:
        if "non_compliant" in resource.get("address", ""):
            return resource, related
    pytest.fail("Non-compliant DocumentDB cluster not found in sample plan")


class TestDocumentDb:
    @staticmethod
    def _extract_outcome(outcome) -> tuple[bool, str, bool]:
        if len(outcome) == 3:
            met, detail, not_applicable = outcome
            return met, detail, not_applicable
        met, detail = outcome
        return met, detail, False

    def test_control_count(self, documentdb_module):
        assert len(documentdb_module.controls()) == 55

    def test_controls_load_from_json_resource(self, documentdb_module):
        with resources.files(stig_modules).joinpath("stigs/documentdb_controls.json").open(encoding="utf-8") as handle:
            control_data = handle.read()

        assert len(documentdb_module.controls()) == control_data.count('"vuln_id"')

    def test_finds_only_documentdb_clusters(self, documentdb_resources):
        addresses = [resource.get("address") for resource, _related in documentdb_resources]
        assert addresses == [
            "aws_docdb_cluster.compliant",
            "aws_docdb_cluster.non_compliant",
        ]

    def test_matches_parameter_group_subnet_group_and_instance(self, compliant_resource):
        _resource, related = compliant_resource
        related_types = {resource.get("type") for resource in related}
        assert related_types == {
            "aws_docdb_cluster_instance",
            "aws_docdb_cluster_parameter_group",
            "aws_docdb_subnet_group",
        }

    def test_compliant_cluster_meets_every_control(self, documentdb_module, compliant_resource):
        resource, related = compliant_resource
        for control in documentdb_module.controls():
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"
            if not_applicable:
                assert "requires manual review" in detail
                continue
            assert "AWS documentation evidence: " in detail
            assert "https://docs.aws.amazon.com/documentdb/" in detail
            if not control.csp_inherited:
                assert "https://registry.terraform.io/providers/hashicorp/aws/" in detail

    def test_fips_tls_is_not_applicable_outside_supported_regions(self, documentdb_module, compliant_resource):
        resource, related = compliant_resource
        regional = {
            **resource,
            "values": {**resource["values"], "region": "eu-west-1"},
        }
        related = [
            item for item in related if item.get("type") != "aws_docdb_cluster_parameter_group"
        ]
        related.append({
            "type": "aws_docdb_cluster_parameter_group",
            "values": {"parameter": [{"name": "tls", "value": "tls1.2+"}]},
        })
        control = next(item for item in documentdb_module.controls() if item.vuln_id == "V-279354")

        met, detail, not_applicable = self._extract_outcome(control.check(regional, related))

        assert met
        assert not_applicable
        assert "eu-west-1" in detail

    def test_partial_audit_events_do_not_satisfy_generation(self, documentdb_module, compliant_resource):
        resource, related = compliant_resource
        control = next(item for item in documentdb_module.controls() if item.vuln_id == "V-279334")
        partial = [
            resource_item
            for resource_item in related
            if resource_item.get("type") != "aws_docdb_cluster_parameter_group"
        ]
        partial.append({
            "type": "aws_docdb_cluster_parameter_group",
            "values": {"parameter": [{"name": "audit_logs", "value": "ddl,dml_write"}]},
        })

        met, detail = control.check(resource, partial)

        assert not met
        assert "ddl,dml_write" in detail

    def test_non_compliant_failures(self, documentdb_module, non_compliant_resource):
        resource, related = non_compliant_resource
        failed = set()
        for control in documentdb_module.controls():
            met, _detail, _not_applicable = self._extract_outcome(control.check(resource, related))
            if not met:
                failed.add(control.vuln_id)
                if control.remediation_comment:
                    assert "Terraform remediation: configure" in control.remediation_comment

        assert failed == EXPECTED_FAILURES
