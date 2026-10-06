import json
from importlib import resources

import pytest

from stig_automator.plan_parser import walk_resources
import stig_automator.modules as stig_modules
from stig_automator.registry import get_module


with resources.files(stig_modules).joinpath("mappings/aks_controls.json").open(encoding="utf-8") as f:
    AKS_CONTROL_MAPPINGS = json.load(f)
AKS_CONTROL_BEHAVIORS = AKS_CONTROL_MAPPINGS["controls"]
AKS_EFFECTIVE_MANUAL_SCOPE_IDS = {
    vuln_id
    for vuln_id, behavior in AKS_CONTROL_BEHAVIORS.items()
    if behavior.get("cklb_status") == "open"
}
AKS_INHERITED_IDS = {
    vuln_id
    for vuln_id, behavior in AKS_CONTROL_BEHAVIORS.items()
    if behavior.get("include_in_blank_cklb") and behavior.get("evidence_key") == "inherited"
}


@pytest.fixture
def aks_module():
    return get_module("aks")


@pytest.fixture
def aks_resources(aks_plan, aks_module):
    all_res = walk_resources(aks_plan)
    return aks_module.find_resources(all_res)


@pytest.fixture
def compliant_resource(aks_resources):
    for res, related in aks_resources:
        if "compliant_cluster" in res.get("address", ""):
            return res, related
    pytest.fail("Compliant cluster not found in sample plan")


@pytest.fixture
def non_compliant_resource(aks_resources):
    for res, related in aks_resources:
        if "non_compliant_cluster" in res.get("address", ""):
            return res, related
    pytest.fail("Non-compliant cluster not found in sample plan")


class TestAksCompliant:
    @staticmethod
    def _extract_met_detail(outcome) -> tuple[bool, str]:
        if len(outcome) == 3:
            met, detail, _na = outcome
            return met, detail
        met, detail = outcome
        return met, detail

    def test_automated_and_true_not_applicable_controls_met(self, aks_module, compliant_resource):
        resource, related = compliant_resource
        for control in aks_module.controls():
            if control.vuln_id in AKS_EFFECTIVE_MANUAL_SCOPE_IDS:
                continue
            met, detail = self._extract_met_detail(control.check(resource, related))
            assert met, f"{control.vuln_id} ({control.stig_id}) failed: {detail}"

    def test_control_count(self, aks_module):
        assert len(aks_module.controls()) == 94

    def test_catalog_and_control_mappings_load_from_json_resources(self, aks_module):
        with resources.files(stig_modules).joinpath("stigs/kubernetes_catalog.json").open(encoding="utf-8") as f:
            catalog = json.load(f)
        with resources.files(stig_modules).joinpath("mappings/aks_controls.json").open(encoding="utf-8") as f:
            mappings = json.load(f)

        assert len(aks_module.controls()) == len(catalog)
        assert "AKS managed-service baseline" in mappings["default"]["automatic_platform_text"]
        assert mappings["controls"]["V-242382"]["validation_function_name"] == "rbac_enabled"
        assert mappings["controls"]["V-274884"]["cklb_status"] == "open"

    def test_metadata_loads_from_json_resource(self, aks_module):
        with resources.files(stig_modules).joinpath("stigs/kubernetes_metadata.json").open(encoding="utf-8") as f:
            metadata = json.load(f)

        control = {c.vuln_id: c for c in aks_module.controls()}["V-242434"]
        source = metadata["V-242434"]
        assert source["rule_id"] == "SV-242434r961131_rule"
        assert "ps -ef | grep kubelet" in source["check_content"]
        assert control.rule_id == source["rule_id"]
        assert control.check_content == source["check_content"]


class TestAksNonCompliant:
    def test_expected_failures(self, aks_module, non_compliant_resource):
        resource, related = non_compliant_resource
        controls = aks_module.controls()
        failed_ids = set()
        for control in controls:
            outcome = control.check(resource, related)
            met = outcome[0]
            if not met:
                failed_ids.add(control.vuln_id)

        # These should definitely fail on the non-compliant cluster
        expected_failures = {
            "V-242443",  # Kubernetes version update cadence (auto-upgrade)
            "V-274883",  # External secret store usage
        }
        for vuln_id in expected_failures:
            assert vuln_id in failed_ids, f"{vuln_id} should have failed but passed"

    def test_failed_terraform_controls_include_remediation_comments(self, aks_module, non_compliant_resource):
        resource, related = non_compliant_resource
        for control in aks_module.controls():
            outcome = control.check(resource, related)
            met = outcome[0]
            not_applicable = len(outcome) == 3 and outcome[2]
            if not met and not not_applicable and control.remediation_comment:
                assert "Terraform remediation: configure" in control.remediation_comment
                assert "https://registry.terraform.io/providers/hashicorp/azurerm/" in control.remediation_comment
                assert "azurerm_" in control.remediation_comment


class TestAksManagedDefaultsEvidence:
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
        assert "https://learn.microsoft.com/en-us/azure/aks/" in detail, (
            f"{control_id} detail should include Azure documentation links"
        )

    def test_managed_defaults_controls_include_quotes_and_links(self, aks_module, compliant_resource):
        resource, related = compliant_resource
        controls_by_id = {c.vuln_id: c for c in aks_module.controls()}
        auto_met_managed_defaults = {
            "V-242386",
            "V-242388",
            "V-242434",
            "V-242444",
            "V-274882",
        }

        for vuln_id in auto_met_managed_defaults:
            control = controls_by_id[vuln_id]
            met, detail, _not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{vuln_id} should be met by AKS managed defaults"
            self._assert_microsoft_learn_evidence(vuln_id, detail)
            assert "Inherited CSP/baseline controls:" in detail

    def test_strict_manual_scope_controls_are_not_proxy_checked(self, aks_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in aks_module.controls()}

        for vuln_id in {"V-242436", "V-242437", "V-254800", "V-274884"}:
            met, detail, not_applicable = self._extract_outcome(controls[vuln_id].check(resource, related))
            assert not met
            assert not not_applicable
            assert "manual review" in detail
            assert "manual" in detail.lower()
            assert "azure_policy_enabled" not in detail
            assert "role_based_access_control_enabled" not in detail

    def test_recommended_platform_controls_are_inherited_not_findings(self, aks_module, compliant_resource):
        resource, related = compliant_resource
        controls = {control.vuln_id: control for control in aks_module.controls()}

        for vuln_id in {"V-242381", "V-242398", "V-245544", "V-254801"}:
            control = controls[vuln_id]
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert control.csp_inherited
            assert met, f"{vuln_id} should be met by AKS managed control-plane evidence"
            assert not not_applicable
            assert "manual review" not in detail
            self._assert_microsoft_learn_evidence(vuln_id, detail)

    def test_static_pod_path_is_node_managed_not_finding(self, aks_module, compliant_resource):
        resource, related = compliant_resource
        control = {control.vuln_id: control for control in aks_module.controls()}["V-242397"]

        met, detail, not_applicable = self._extract_outcome(control.check(resource, related))

        assert control.csp_inherited
        assert met
        assert not not_applicable
        assert "AKS managed node baseline evidence" in detail
        self._assert_microsoft_learn_evidence("V-242397", detail)

    def test_all_inherited_controls_include_quotes_and_links(self, aks_module, compliant_resource):
        resource, related = compliant_resource

        inherited_controls = [control for control in aks_module.controls() if control.csp_inherited]
        assert inherited_controls, "AKS should expose CSP-inherited controls"

        for control in inherited_controls:
            met, detail, _not_applicable = self._extract_outcome(control.check(resource, related))
            assert met, f"{control.vuln_id} should be met by inherited AKS evidence"
            self._assert_microsoft_learn_evidence(control.vuln_id, detail)
            assert "Inherited CSP/baseline controls:" in detail

    def test_inherited_paas_controls_are_not_findings_not_na(self, aks_module, compliant_resource):
        resource, related = compliant_resource

        inherited_results = []
        for control in aks_module.controls():
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            if control.vuln_id in AKS_INHERITED_IDS:
                inherited_results.append((control.vuln_id, met, not_applicable, detail))

        assert inherited_results, "AKS should have inherited PaaS controls"

        for vuln_id, met, not_applicable, detail in inherited_results:
            assert met, f"{vuln_id} should be met as an inherited PaaS control"
            assert not_applicable is False, f"{vuln_id} should be not a finding, not N/A"
            self._assert_microsoft_learn_evidence(vuln_id, detail)

    def test_manual_scope_controls_are_open_not_not_applicable(self, aks_module, compliant_resource):
        resource, related = compliant_resource
        for control in aks_module.controls():
            if control.vuln_id not in AKS_EFFECTIVE_MANUAL_SCOPE_IDS:
                continue
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            assert met is False, f"{control.vuln_id} should remain open pending manual review"
            assert not_applicable is False, f"{control.vuln_id} should not be marked not applicable"
            assert "manual review" in detail

    def test_all_met_or_not_applicable_controls_include_quotes_and_links(self, aks_module, compliant_resource):
        resource, related = compliant_resource

        for control in aks_module.controls():
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            if met or not_applicable:
                self._assert_microsoft_learn_evidence(control.vuln_id, detail)

    def test_direct_met_controls_include_terraform_provider_links(self, aks_module, compliant_resource):
        resource, related = compliant_resource

        for control in aks_module.controls():
            met, detail, not_applicable = self._extract_outcome(control.check(resource, related))
            if met and not not_applicable and not control.csp_inherited:
                assert "Terraform properties addressed:" in detail
                assert "https://registry.terraform.io/providers/hashicorp/azurerm/" in detail, (
                    f"{control.vuln_id} detail should include Terraform provider documentation"
                )


class TestAksResourceDiscovery:
    def test_finds_both_resources(self, aks_resources):
        assert len(aks_resources) == 2

    def test_resource_has_expected_keys(self, aks_resources):
        for res, related in aks_resources:
            assert "address" in res
            assert "type" in res
            assert "values" in res
