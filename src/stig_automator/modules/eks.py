"""Amazon EKS Kubernetes STIG module for Fargate and managed node groups."""

from __future__ import annotations

from typing import Callable

from ..models import Severity, StigControl
from ..plan_parser import filter_by_type
from ..registry import register
from ..util import first_nested, get_nested
from ._aws import load_json_file, remediation_comment, truthy, with_aws_evidence
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

K8S_STIG_CATALOG_FILE = "stigs/kubernetes_catalog.json"
K8S_STIG_METADATA_FILE = "stigs/kubernetes_metadata.json"
EKS_CONTROL_MAPPINGS_FILE = "mappings/eks_controls.json"
EKS_EVIDENCE_FILE = "mappings/eks_evidence.json"

K8S_STIG_CATALOG: list[dict[str, str]] = list(load_json_file(K8S_STIG_CATALOG_FILE))
K8S_STIG_METADATA: dict[str, dict[str, object]] = dict(load_json_file(K8S_STIG_METADATA_FILE))
EKS_CONTROL_MAPPING_DATA: dict[str, object] = dict(load_json_file(EKS_CONTROL_MAPPINGS_FILE))
EKS_EVIDENCE: dict[str, dict[str, object]] = dict(load_json_file(EKS_EVIDENCE_FILE))


def _with_evidence(detail: str, evidence_key: str) -> str:
    return with_aws_evidence(detail, evidence_key, EKS_EVIDENCE)


def _remediation_comment(evidence_key: str) -> str:
    return remediation_comment(evidence_key, EKS_EVIDENCE)


def _control_plane_log_types(cluster: dict) -> set[str]:
    return {str(item) for item in get_nested(cluster, "values", "enabled_cluster_log_types", default=[]) or []}


def _is_open_public_cidr(value: object) -> bool:
    return str(value).strip() in {"0.0.0.0/0", "::/0"}


def _cluster_version(cluster: dict) -> tuple[int, int] | None:
    version = str(get_nested(cluster, "values", "version", default=""))
    parts = version.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return None


def _has_fargate_profile(related: list[dict]) -> bool:
    return any(resource.get("type") == "aws_eks_fargate_profile" for resource in related)


def _has_managed_node_group(related: list[dict]) -> bool:
    return any(resource.get("type") == "aws_eks_node_group" for resource in related)


def _check_rbac_enabled(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    access_config = first_nested(cluster, "values", "access_config") or {}
    mode = str(get_nested(access_config, "authentication_mode", default=""))
    if mode in {"API", "API_AND_CONFIG_MAP"}:
        return True, _with_evidence(
            f"access_config.authentication_mode={mode}; EKS integrates IAM authentication with Kubernetes RBAC.",
            "rbac_enabled",
        )
    return False, f"access_config.authentication_mode={mode or 'not configured'}; expected API or API_AND_CONFIG_MAP."


def _check_api_endpoint_private(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    vpc_config = first_nested(cluster, "values", "vpc_config") or {}
    private = get_nested(vpc_config, "endpoint_private_access")
    public = get_nested(vpc_config, "endpoint_public_access")
    cidrs = get_nested(vpc_config, "public_access_cidrs", default=[]) or []
    public_restricted = not truthy(public) or (cidrs and not any(_is_open_public_cidr(cidr) for cidr in cidrs))
    if truthy(private) and public_restricted:
        return True, _with_evidence(
            f"endpoint_private_access={private}, endpoint_public_access={public}, public_access_cidrs={cidrs}.",
            "api_endpoint_private",
        )
    return False, "endpoint_private_access must be true and public access must be disabled or CIDR-restricted."


def _check_control_plane_logs(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    logs = _control_plane_log_types(cluster)
    required = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
    if required <= logs:
        return True, _with_evidence(
            f"enabled_cluster_log_types includes {', '.join(sorted(logs))}.",
            "control_plane_logs",
        )
    return False, f"enabled_cluster_log_types missing: {', '.join(sorted(required - logs))}."


def _check_secrets_encryption(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    for config in get_nested(cluster, "values", "encryption_config", default=[]) or []:
        resources = {str(item).lower() for item in get_nested(config, "resources", default=[]) or []}
        provider = first_nested(config, "provider") or {}
        if "secrets" in resources and get_nested(provider, "key_arn"):
            return True, _with_evidence(
                "encryption_config covers secrets with a KMS key.",
                "secrets_encryption",
            )
    version = _cluster_version(cluster)
    if version and version >= (1, 28):
        return True, _with_evidence(
            f"version={version[0]}.{version[1]}; EKS enables envelope encryption by default for this version.",
            "secrets_encryption_default",
        )
    return False, "encryption_config for secrets is missing and cluster version is below 1.28."


def _check_irsa_oidc(cluster: dict, related: list[dict]) -> tuple[bool, str]:
    identity = first_nested(cluster, "values", "identity") or {}
    oidc = first_nested(identity, "oidc") or {}
    issuer = str(get_nested(oidc, "issuer", default=""))
    for resource in related:
        if resource.get("type") == "aws_iam_openid_connect_provider":
            url = str(get_nested(resource, "values", "url", default=""))
            if issuer and url and issuer.rstrip("/") == url.rstrip("/"):
                return True, _with_evidence(
                    f"OIDC provider {url} matches cluster issuer for IAM roles for service accounts.",
                    "irsa_oidc",
                )
    return False, "No aws_iam_openid_connect_provider matches the EKS cluster OIDC issuer."


def _check_compute_mode(_cluster: dict, related: list[dict]) -> tuple[bool, str]:
    has_fargate = _has_fargate_profile(related)
    has_nodes = _has_managed_node_group(related)
    if has_fargate and has_nodes:
        return True, _with_evidence(
            "aws_eks_fargate_profile and aws_eks_node_group resources are both associated with the cluster.",
            "compute_modes",
        )
    if has_fargate:
        return True, _with_evidence(
            "aws_eks_fargate_profile is associated with the cluster.",
            "fargate_profile",
        )
    if has_nodes:
        return True, _with_evidence(
            "aws_eks_node_group is associated with the cluster.",
            "managed_node_group",
        )
    return False, "No aws_eks_fargate_profile or aws_eks_node_group resources are associated with the cluster."


def _check_fargate_profile(_cluster: dict, related: list[dict]) -> tuple[bool, str]:
    profiles = [resource for resource in related if resource.get("type") == "aws_eks_fargate_profile"]
    if not profiles:
        return True, _with_evidence(
            "No Fargate profile is associated with this cluster; Fargate-specific controls are not applicable.",
            "fargate_not_configured",
        )
    for profile in profiles:
        selectors = get_nested(profile, "values", "selector", default=[]) or []
        subnets = get_nested(profile, "values", "subnet_ids", default=[]) or []
        role = get_nested(profile, "values", "pod_execution_role_arn")
        if not selectors or not subnets or not role:
            return False, f"{profile.get('address', 'aws_eks_fargate_profile')} lacks selectors, subnets, or pod role."
    return True, _with_evidence(
        f"{len(profiles)} Fargate profile(s) have selectors, subnets, and pod execution roles.",
        "fargate_profile",
    )


def _check_managed_node_group(cluster: dict, related: list[dict]) -> tuple[bool, str]:
    groups = [resource for resource in related if resource.get("type") == "aws_eks_node_group"]
    if not groups:
        return True, _with_evidence(
            "No managed node group is associated with this cluster; managed-node controls are not applicable.",
            "managed_nodes_not_configured",
        )
    cluster_version = str(get_nested(cluster, "values", "version", default=""))
    for group in groups:
        scaling = first_nested(group, "values", "scaling_config") or {}
        desired = get_nested(scaling, "desired_size")
        minimum = get_nested(scaling, "min_size")
        maximum = get_nested(scaling, "max_size")
        remote_access = first_nested(group, "values", "remote_access")
        node_version = str(get_nested(group, "values", "version", default=cluster_version))
        if desired is None or minimum is None or maximum is None:
            return False, f"{group.get('address', 'aws_eks_node_group')} lacks scaling_config."
        if remote_access:
            return False, f"{group.get('address', 'aws_eks_node_group')} enables remote_access."
        if cluster_version and node_version and cluster_version != node_version:
            return False, f"{group.get('address', 'aws_eks_node_group')} version {node_version} differs from {cluster_version}."
    return True, _with_evidence(
        f"{len(groups)} managed node group(s) have scaling config, no remote_access, and cluster-matching versions.",
        "managed_node_group",
    )


def _check_addons(cluster: dict, related: list[dict]) -> tuple[bool, str]:
    names = {
        str(get_nested(resource, "values", "addon_name", default=""))
        for resource in related
        if resource.get("type") == "aws_eks_addon"
    }
    required = {"vpc-cni", "coredns", "kube-proxy"}
    version = _cluster_version(cluster)
    if required <= names and version and version >= (1, 28):
        return True, _with_evidence(
            f"managed EKS add-ons configured: {', '.join(sorted(names))}.",
            "addons",
        )
    if not required <= names:
        return False, f"missing managed EKS add-ons: {', '.join(sorted(required - names))}."
    return False, "cluster version must be 1.28 or newer for the configured add-on baseline."


def _managed_evidence_detail(
    evidence_key: str,
    vuln_id: str,
    title: str,
    related: list[dict],
    detail_template: str,
) -> str:
    evidence = EKS_EVIDENCE[evidence_key]
    segments = [
        f"\"{quote['quote']}\" ({quote['url']})"
        for quote in evidence["quotes"]
    ]
    compute = "Fargate and managed node"
    if _has_fargate_profile(related) and not _has_managed_node_group(related):
        compute = "Fargate"
    elif _has_managed_node_group(related) and not _has_fargate_profile(related):
        compute = "managed node"
    summary = detail_template.format(vuln_id=vuln_id, title=title, compute=compute)
    return f"AWS documentation evidence: {' '.join(segments)} Inherited CSP/baseline controls: {summary}"


def _platform_detail(
    mapping: ControlMapping,
    vuln_id: str,
    title: str,
    related: list[dict],
) -> str:
    return _managed_evidence_detail(
        mapping.evidence_key,
        vuln_id,
        title,
        related,
        mapping.automatic_platform_text,
    )


SEVERITY_MAP: dict[str, Severity] = {
    "high": Severity.CAT_I,
    "medium": Severity.CAT_II,
    "low": Severity.CAT_III,
}
CONTROL_CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str] | tuple[bool, str, bool]]] = {
    "rbac_enabled": _check_rbac_enabled,
    "api_endpoint_private": _check_api_endpoint_private,
    "control_plane_logs": _check_control_plane_logs,
    "secrets_encryption": _check_secrets_encryption,
    "irsa_oidc": _check_irsa_oidc,
    "compute_mode": _check_compute_mode,
    "fargate_profile": _check_fargate_profile,
    "managed_node_group": _check_managed_node_group,
    "addons": _check_addons,
}
EKS_CONTROL_MAPPINGS = load_control_mappings(
    EKS_CONTROL_MAPPING_DATA,
    module_name="eks",
    validation_functions=CONTROL_CHECKS,
    evidence_keys=set(EKS_EVIDENCE),
)


def _build_controls() -> list[StigControl]:
    controls: list[StigControl] = []
    for entry in K8S_STIG_CATALOG:
        vuln_id = entry["vuln_id"]
        metadata = K8S_STIG_METADATA.get(vuln_id, {})
        title = str(metadata.get("title") or entry["title"])
        description = str(metadata.get("description") or entry["description"])
        mapping = EKS_CONTROL_MAPPINGS.for_control(vuln_id)
        if mapping.validation_function_name:
            check = CONTROL_CHECKS[mapping.validation_function_name]
            csp_inherited = False
            remediation = _remediation_comment(mapping.remediation_key) if mapping.remediation_key else ""
        else:
            check = make_platform_check(
                mapping,
                lambda item, _resource, related, vuln_id=vuln_id, title=title: _platform_detail(
                    item,
                    vuln_id,
                    title,
                    related,
                ),
            )
            csp_inherited = mapping.include_in_blank_cklb
            remediation = ""

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
                remediation_comment=remediation,
            ),
        )
    return controls


STIG_CONTROLS: list[StigControl] = _build_controls()


@register
class EksStigModule(BaseStigModule):
    """Amazon EKS Kubernetes STIG compliance module."""

    name = "eks"
    description = "Kubernetes STIG (DISA STIG for Kubernetes, V2) — aws_eks_cluster"
    resource_type = "aws_eks_cluster"
    related_resource_types = {
        "aws_eks_addon",
        "aws_eks_fargate_profile",
        "aws_eks_node_group",
        "aws_iam_openid_connect_provider",
    }
    report_title = "Amazon EKS STIG Report"

    stig_benchmark_id = "Kubernetes_STIG"
    stig_benchmark_title = "Kubernetes Security Technical Implementation Guide"
    stig_version = "2"
    stig_release_info = "Release: 4 Benchmark Date: 02 Jul 2025"

    def controls(self) -> list[StigControl]:
        """Return the EKS Kubernetes STIG control catalogue."""
        return STIG_CONTROLS

    def find_resources(self, all_resources: list[dict]) -> list[tuple[dict, list[dict]]]:
        """Find EKS clusters and matching Fargate, managed node, add-on, and OIDC resources."""
        primaries = filter_by_type(all_resources, self.resource_type)
        related = [resource for resource in all_resources if resource.get("type") in self.related_resource_types]

        result = []
        for primary in primaries:
            cluster_name = get_nested(primary, "values", "name", default="")
            identity = first_nested(primary, "values", "identity") or {}
            oidc = first_nested(identity, "oidc") or {}
            issuer = str(get_nested(oidc, "issuer", default="")).rstrip("/")
            matched = []
            for resource in related:
                related_cluster = get_nested(resource, "values", "cluster_name", default="")
                addon_cluster = get_nested(resource, "values", "cluster_name", default="")
                oidc_url = str(get_nested(resource, "values", "url", default="")).rstrip("/")
                if (
                    (cluster_name and related_cluster == cluster_name)
                    or (cluster_name and addon_cluster == cluster_name)
                    or (issuer and oidc_url == issuer)
                ):
                    matched.append(resource)
            result.append((primary, matched))
        return result
