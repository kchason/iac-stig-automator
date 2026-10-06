import json
from importlib import resources

import pytest

from stig_automator.plan_parser import walk_resources
import stig_automator.modules as stig_modules
from stig_automator.registry import get_module


with resources.files(stig_modules).joinpath("mappings/eks_controls.json").open(encoding="utf-8") as f:
    EKS_CONTROL_MAPPINGS = json.load(f)
EKS_CONTROL_BEHAVIORS = EKS_CONTROL_MAPPINGS["controls"]
EKS_EFFECTIVE_MANUAL_SCOPE_IDS = {
    vuln_id
    for vuln_id, behavior in EKS_CONTROL_BEHAVIORS.items()
    if behavior.get("cklb_status") == "open"
}


@pytest.fixture
def eks_module():
    return get_module("eks")


@pytest.fixture
def eks_resources(eks_plan, eks_module):
    all_resources = walk_resources(eks_plan)
    return eks_module.find_resources(all_resources)


@pytest.fixture
def compliant_resource(eks_resources):
    for resource, related in eks_resources:
        if "compliant_cluster" in resource.get("address", "") and "non" not in resource.get("address", ""):
            return resource, related
    pytest.fail("Compliant EKS cluster not found in sample plan")


@pytest.fixture
def non_compliant_resource(eks_resources):
    for resource, related in eks_resources:
        if "non_compliant_cluster" in resource.get("address", ""):
            return resource, related
    pytest.fail("Non-compliant EKS cluster not found in sample plan")


class TestEksCompliant:
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
        assert "https://docs.aws.amazon.com/eks/" in detail or "https://docs.aws.amazon.com/EKS/" in detail

    def test_automated_and_true_not_applicable_controls_met(self, eks_module, compliant_resource):
        resource, related = compliant_resource
        for control in eks_module.controls():
            if control.vuln_id in EKS_EFFECTIVE_MANUAL_SCOPE_IDS:
                continue
            met, detail, _not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"

    def test_control_count(self, eks_module):
        assert len(eks_module.controls()) == 94

    def test_catalog_and_control_mappings_load_from_json_resources(self, eks_module):
        with resources.files(stig_modules).joinpath("stigs/kubernetes_catalog.json").open(encoding="utf-8") as f:
            catalog = json.load(f)
        with resources.files(stig_modules).joinpath("mappings/eks_controls.json").open(encoding="utf-8") as f:
            mappings = json.load(f)

        assert len(eks_module.controls()) == len(catalog)
        assert "EKS managed-service baseline" in mappings["default"]["automatic_platform_text"]
        assert mappings["controls"]["V-242382"]["validation_function_name"] == "rbac_enabled"
        assert mappings["controls"]["V-242381"]["cklb_status"] == "open"
        assert mappings["controls"]["V-242434"]["include_in_blank_cklb"] is True

    def test_direct_met_controls_include_aws_and_terraform_links(self, eks_module, compliant_resource):
        resource, related = compliant_resource
        for control in eks_module.controls():
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            if met and not not_applicable and not control.csp_inherited:
                self._assert_aws_evidence(control.vuln_id, detail)
                assert "Terraform properties addressed:" in detail
                assert "https://registry.terraform.io/providers/hashicorp/aws/" in detail

    def test_inherited_controls_include_aws_documentation(self, eks_module, compliant_resource):
        resource, related = compliant_resource
        inherited_controls = [control for control in eks_module.controls() if control.csp_inherited]
        assert inherited_controls
        for control in inherited_controls:
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} should be met by inherited EKS evidence"
            assert not_applicable is False, f"{control.vuln_id} should be not a finding, not N/A"
            self._assert_aws_evidence(control.vuln_id, detail)
            assert "Inherited CSP/baseline controls:" in detail

    def test_strict_manual_scope_controls_are_not_proxy_checked(self, eks_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in eks_module.controls()}

        for vuln_id in {"V-242381", "V-274883", "V-274884"}:
            met, detail, not_applicable = self._extract_outcome(controls[vuln_id].check(resource, related))
            assert not met
            assert not not_applicable
            assert "manual review" in detail
            assert "OIDC" not in detail
            assert "encryption_config" not in detail

    def test_manual_scope_controls_are_open_not_not_applicable(self, eks_module, compliant_resource):
        resource, related = compliant_resource
        for control in eks_module.controls():
            if control.vuln_id not in EKS_EFFECTIVE_MANUAL_SCOPE_IDS:
                continue
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert met is False, f"{control.vuln_id} should remain open pending manual review"
            assert not_applicable is False, f"{control.vuln_id} should not be marked not applicable"
            assert "manual review" in detail


class TestEksNonCompliant:
    def test_expected_failures(self, eks_module, non_compliant_resource):
        resource, related = non_compliant_resource
        failed_ids = set()
        for control in eks_module.controls():
            outcome = control.check(resource, related)
            if not outcome[0]:
                failed_ids.add(control.vuln_id)

        expected_failures = {
            "V-242382",
            "V-242402",
            "V-242403",
            "V-242443",
            "V-242461",
            "V-242465",
            "V-274882",
        }
        assert expected_failures <= failed_ids

    def test_failed_terraform_controls_include_remediation_comments(self, eks_module, non_compliant_resource):
        resource, related = non_compliant_resource
        for control in eks_module.controls():
            outcome = control.check(resource, related)
            not_applicable = len(outcome) == 3 and outcome[2]
            if not outcome[0] and not not_applicable and control.remediation_comment:
                assert "Terraform remediation: configure" in control.remediation_comment
                assert "https://registry.terraform.io/providers/hashicorp/aws/" in control.remediation_comment
                assert "aws_" in control.remediation_comment


class TestEksResourceDiscovery:
    def test_finds_both_clusters(self, eks_resources):
        assert len(eks_resources) == 2

    def test_compliant_resource_has_fargate_and_managed_nodes(self, compliant_resource):
        _resource, related = compliant_resource
        related_types = {resource["type"] for resource in related}
        assert "aws_eks_fargate_profile" in related_types
        assert "aws_eks_node_group" in related_types
        assert "aws_eks_addon" in related_types
        assert "aws_iam_openid_connect_provider" in related_types
