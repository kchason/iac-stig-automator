"""AKS Kubernetes STIG module — full Kubernetes STIG catalog for AKS."""

from __future__ import annotations

import json
from importlib import resources
from typing import Callable

from ..models import Severity, StigControl
from ..registry import register
from ..util import first_nested, get_nested
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

K8S_STIG_CATALOG_FILE = "stigs/kubernetes_catalog.json"
K8S_STIG_METADATA_FILE = "stigs/kubernetes_metadata.json"
AKS_CONTROL_MAPPINGS_FILE = "mappings/aks_controls.json"
AKS_EVIDENCE_FILE = "mappings/aks_evidence.json"


def _load_json_file(filename: str) -> object:
    with resources.files(__package__).joinpath(filename).open(encoding="utf-8") as f:
        return json.load(f)


K8S_STIG_CATALOG: list[dict[str, str]] = list(_load_json_file(K8S_STIG_CATALOG_FILE))
K8S_STIG_METADATA: dict[str, dict[str, object]] = dict(_load_json_file(K8S_STIG_METADATA_FILE))
AKS_CONTROL_MAPPING_DATA: dict[str, object] = dict(_load_json_file(AKS_CONTROL_MAPPINGS_FILE))
AKS_EVIDENCE: dict[str, dict[str, object]] = dict(_load_json_file(AKS_EVIDENCE_FILE))


# ---------------------------------------------------------------------------
# Concrete Terraform-driven checks for selected controls
# ---------------------------------------------------------------------------

def _with_microsoft_learn_evidence(detail: str, evidence_key: str) -> str:
    evidence = AKS_EVIDENCE[evidence_key]
    quote = str(evidence["quote"])
    url = str(evidence["url"])
    terraform_urls = [str(item) for item in evidence.get("terraform_urls", [])]
    properties = [str(item) for item in evidence.get("terraform_properties", [])]
    terraform_properties = ""
    if properties:
        terraform_properties = f" Terraform properties addressed: {'; '.join(properties)}."
    terraform_docs = ""
    if terraform_urls:
        terraform_docs = f" Terraform provider docs: {', '.join(terraform_urls)}"
    return f"{detail} Microsoft Learn evidence: \"{quote}\" ({url}){terraform_properties}{terraform_docs}"


def _remediation_comment(evidence_key: str) -> str:
    evidence = AKS_EVIDENCE[evidence_key]
    terraform_urls = [str(item) for item in evidence.get("terraform_urls", [])]
    properties = [str(item) for item in evidence.get("terraform_properties", [])]
    if not terraform_urls or not properties:
        return ""
    return (
        "Terraform remediation: configure "
        f"{'; '.join(properties)}. Provider docs: {', '.join(terraform_urls)}"
    )


def _check_rbac_enabled(r: dict, _related: list[dict]) -> tuple[bool, str]:
    enabled = get_nested(r, "values", "role_based_access_control_enabled", default=True)
    aad_rbac = first_nested(r, "values", "azure_active_directory_role_based_access_control") or {}
    azure_rbac = get_nested(aad_rbac, "azure_rbac_enabled", default=False)
    if enabled and azure_rbac:
        return True, _with_microsoft_learn_evidence(
            "role_based_access_control_enabled=true and azure_rbac_enabled=true — RBAC is active and "
            "Azure authorization decisions are enforced at the API server.",
            "rbac_enabled_azure",
        )
    if enabled:
        return True, _with_microsoft_learn_evidence(
            f"role_based_access_control_enabled=true (azure_rbac_enabled={azure_rbac}) — Kubernetes RBAC is enabled.",
            "rbac_enabled_kubernetes",
        )
    return False, "role_based_access_control_enabled=false - RBAC is disabled"


def _check_auto_upgrade(r: dict, _related: list[dict]) -> tuple[bool, str]:
    channel = get_nested(r, "values", "automatic_channel_upgrade")
    if not channel:
        channel = get_nested(r, "values", "automatic_upgrade_channel")
    if channel and channel.lower() != "none":
        return True, _with_microsoft_learn_evidence(
            f"automatic_channel_upgrade={channel} — An auto-upgrade channel is configured so the cluster "
            "receives Kubernetes security and version updates automatically.",
            "auto_upgrade",
        )
    return False, "automatic_channel_upgrade not set - cluster will not receive automatic Kubernetes version upgrades"


def _check_key_vault_secrets_provider(r: dict, _related: list[dict]) -> tuple[bool, str]:
    kv = first_nested(r, "values", "key_vault_secrets_provider")
    if kv:
        return True, _with_microsoft_learn_evidence(
            f"key_vault_secrets_provider enabled (secret_rotation_enabled={get_nested(kv, 'secret_rotation_enabled', default=False)}) "
            "— The CSI Secrets Store driver with Azure Key Vault integration is configured.",
            "key_vault_secrets_provider",
        )
    return False, "key_vault_secrets_provider not configured"


def _check_azure_policy_addon(r: dict, _related: list[dict]) -> tuple[bool, str]:
    enabled = get_nested(r, "values", "azure_policy_enabled", default=False)
    if enabled:
        return True, _with_microsoft_learn_evidence(
            "azure_policy_enabled=true — The Azure Policy add-on is active and can enforce admission-time "
            "security constraints.",
            "azure_policy_addon",
        )
    return False, "azure_policy_enabled not set - Azure Policy admission controller not active"


# ---------------------------------------------------------------------------
# Managed-service evidence and fallback checks
# ---------------------------------------------------------------------------

def _managed_evidence_detail(
    evidence_key: str,
    vuln_id: str,
    title: str,
    detail_template: str,
) -> str:
    evidence = AKS_EVIDENCE[evidence_key]
    segments = [
        f"\"{quote['quote']}\" ({quote['url']})"
        for quote in evidence["quotes"]
    ]
    summary = detail_template.format(vuln_id=vuln_id, title=title)
    return f"Microsoft Learn evidence: {' '.join(segments)} Inherited CSP/baseline controls: {summary}"


def _platform_detail(
    mapping: ControlMapping,
    vuln_id: str,
    title: str,
) -> str:
    return _managed_evidence_detail(
        mapping.evidence_key,
        vuln_id,
        title,
        mapping.automatic_platform_text,
    )


SEVERITY_MAP: dict[str, Severity] = {
    "high": Severity.CAT_I,
    "medium": Severity.CAT_II,
    "low": Severity.CAT_III,
}

CONTROL_CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str] | tuple[bool, str, bool]]] = {
    "rbac_enabled": _check_rbac_enabled,
    "azure_policy_addon": _check_azure_policy_addon,
    "auto_upgrade": _check_auto_upgrade,
    "key_vault_secrets_provider": _check_key_vault_secrets_provider,
}
AKS_CONTROL_MAPPINGS = load_control_mappings(
    AKS_CONTROL_MAPPING_DATA,
    module_name="aks",
    validation_functions=CONTROL_CHECKS,
    evidence_keys=set(AKS_EVIDENCE),
)


def _build_controls() -> list[StigControl]:
    controls: list[StigControl] = []
    for entry in K8S_STIG_CATALOG:
        vuln_id = entry["vuln_id"]
        metadata = K8S_STIG_METADATA.get(vuln_id, {})
        title = str(metadata.get("title") or entry["title"])
        description = str(metadata.get("description") or entry["description"])
        mapping = AKS_CONTROL_MAPPINGS.for_control(vuln_id)
        if mapping.validation_function_name:
            check = CONTROL_CHECKS[mapping.validation_function_name]
            csp_inherited = False
            remediation_comment = _remediation_comment(mapping.remediation_key) if mapping.remediation_key else ""
        else:
            check = make_platform_check(
                mapping,
                lambda item, _resource, _related, vuln_id=vuln_id, title=title: _platform_detail(
                    item,
                    vuln_id,
                    title,
                ),
            )
            csp_inherited = mapping.include_in_blank_cklb
            remediation_comment = ""

        controls.append(
            StigControl(
                vuln_id=vuln_id,
                stig_id=entry["stig_id"],
                severity=SEVERITY_MAP[entry["severity"]],
                title=title,
                description=description,
                check=check,
                csp_inherited=csp_inherited,
                rule_id=str(metadata.get("rule_id", "")),
                group_title=str(metadata.get("group_title", "")),
                cci=tuple(metadata.get("cci", ())),
                check_content=str(metadata.get("check_content", "")),
                fix_text=str(metadata.get("fix_text", "")),
                false_positives=str(metadata.get("false_positives", "")),
                false_negatives=str(metadata.get("false_negatives", "")),
                documentable=str(metadata.get("documentable", "")),
                mitigations=str(metadata.get("mitigations", "")),
                potential_impacts=str(metadata.get("potential_impacts", "")),
                third_party_tools=str(metadata.get("third_party_tools", "")),
                mitigation_control=str(metadata.get("mitigation_control", "")),
                responsibility=str(metadata.get("responsibility", "")),
                security_override_guidance=str(metadata.get("security_override_guidance", "")),
                check_content_ref=dict(metadata.get("check_content_ref", {})),
                remediation_comment=remediation_comment,
            ),
        )

    return controls


STIG_CONTROLS: list[StigControl] = _build_controls()


@register
class AksStigModule(BaseStigModule):
    """Azure Kubernetes Service STIG compliance module."""

    name = "aks"
    description = "Kubernetes STIG (DISA STIG for Kubernetes, V2) — azurerm_kubernetes_cluster"
    resource_type = "azurerm_kubernetes_cluster"
    related_resource_types: set[str] = set()
    report_title = "AKS STIG Report"

    stig_benchmark_id = "Kubernetes_STIG"
    stig_benchmark_title = "Kubernetes Security Technical Implementation Guide"
    stig_version = "2"
    stig_release_info = "Release: 4 Benchmark Date: 02 Jul 2025"

    def controls(self) -> list[StigControl]:
        """Return the AKS Kubernetes STIG control catalogue."""
        return STIG_CONTROLS
