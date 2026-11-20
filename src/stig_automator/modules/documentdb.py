"""Amazon DocumentDB checks for the MongoDB Enterprise Advanced 8.x STIG."""

from __future__ import annotations

from typing import Callable

from ..models import Severity, StigControl
from ..plan_parser import filter_by_type
from ..registry import register
from ..util import get_nested
from ._aws import (
    csv_tokens,
    engine_major_version,
    load_json_file,
    remediation_comment,
    truthy,
    with_aws_evidence,
)
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

CONTROLS_FILE = "stigs/documentdb_controls.json"
CONTROL_MAPPINGS_FILE = "mappings/documentdb_controls.json"
EVIDENCE_FILE = "mappings/documentdb_evidence.json"

CONTROL_DATA: list[dict[str, object]] = list(load_json_file(CONTROLS_FILE))
CONTROL_MAPPING_DATA: dict[str, object] = dict(load_json_file(CONTROL_MAPPINGS_FILE))
EVIDENCE: dict[str, dict[str, object]] = dict(load_json_file(EVIDENCE_FILE))

TLS_ACCEPTED = {"enabled", "tls1.2+", "tls1.3+", "fips-140-3"}
AUDIT_COMPLETE = {"ddl", "dml_read", "dml_write"}
SUPPORTED_MAJOR_VERSIONS = {4, 5, 8}
FIPS_TLS_REGIONS = {
    "ca-central-1",
    "us-east-1",
    "us-east-2",
    "us-gov-east-1",
    "us-gov-west-1",
    "us-west-2",
}


def _with_evidence(detail: str, evidence_key: str) -> str:
    return with_aws_evidence(detail, evidence_key, EVIDENCE)


def _remediation_comment(evidence_key: str) -> str:
    return remediation_comment(evidence_key, EVIDENCE)


def _platform_detail(mapping: ControlMapping, vuln_id: str, title: str) -> str:
    detail = mapping.automatic_platform_text.format(vuln_id=vuln_id, title=title)
    if not mapping.evidence_key:
        return detail
    evidence = EVIDENCE[mapping.evidence_key]
    quote = str(evidence["quote"])
    url = str(evidence["url"])
    if mapping.include_in_blank_cklb:
        return f'AWS documentation evidence: "{quote}" ({url}) Inherited CSP/baseline controls: {detail}'
    return f'AWS documentation evidence: "{quote}" ({url}) {detail}'


def _parameter_value(related: list[dict], name: str) -> tuple[bool, str]:
    """Return whether a DocumentDB cluster parameter is set, and its value."""
    expected = name.lower()
    for resource in related:
        if resource.get("type") != "aws_docdb_cluster_parameter_group":
            continue
        for parameter in get_nested(resource, "values", "parameter", default=[]) or []:
            if str(get_nested(parameter, "name", default="")).lower() == expected:
                return True, str(get_nested(parameter, "value", default=""))
    return False, ""


def _audit_covers_events(value: str) -> bool:
    tokens = csv_tokens(value)
    if "all" in tokens or "enabled" in tokens:
        return True
    return AUDIT_COMPLETE <= tokens


def _check_tls_required(_cluster: dict, related: list[dict]) -> tuple[bool, str]:
    found, value = _parameter_value(related, "tls")
    normalized = value.strip().lower()
    if not found:
        return True, _with_evidence(
            "tls is unset; Amazon DocumentDB enables encryption in transit by default.",
            "tls_required",
        )
    if normalized in TLS_ACCEPTED:
        return True, _with_evidence(
            f"tls={value}; client connections must use TLS.",
            "tls_required",
        )
    return False, f"tls={value or 'not configured'}; expected enabled, tls1.2+, tls1.3+, or fips-140-3."


def _check_fips_tls(cluster: dict, related: list[dict]) -> tuple[bool, str] | tuple[bool, str, bool]:
    _found, value = _parameter_value(related, "tls")
    if value.strip().lower() == "fips-140-3":
        return True, _with_evidence(
            "tls=fips-140-3; the cluster requires FIPS 140-3 TLS.",
            "fips_tls",
        )
    region = str(get_nested(cluster, "values", "region", default="") or "")
    if region and region not in FIPS_TLS_REGIONS:
        return True, (
            f"tls fips-140-3 is not offered in {region}. "
            "Amazon DocumentDB documents that value for ca-central-1, us-east-1, us-east-2, "
            "us-west-2, us-gov-east-1, and us-gov-west-1."
        ), True
    shown = value or "not configured"
    return False, (
        f"tls={shown}; expected fips-140-3. "
        "DocumentDB supports this value in a limited set of Regions."
    )


def _check_audit_logs(_cluster: dict, related: list[dict]) -> tuple[bool, str]:
    found, value = _parameter_value(related, "audit_logs")
    if found and _audit_covers_events(value):
        return True, _with_evidence(
            f"audit_logs={value}; DocumentDB auditing covers DDL, DML read, and DML write events.",
            "audit_logs",
        )
    shown = value if found else "disabled (default)"
    return False, f"audit_logs={shown}; expected all, enabled, or ddl,dml_read,dml_write."


def _check_audit_offload(cluster: dict, related: list[dict]) -> tuple[bool, str]:
    found, value = _parameter_value(related, "audit_logs")
    exports = {
        str(item).lower()
        for item in get_nested(cluster, "values", "enabled_cloudwatch_logs_exports", default=[]) or []
    }
    if found and _audit_covers_events(value) and "audit" in exports:
        return True, _with_evidence(
            f"audit_logs={value} and enabled_cloudwatch_logs_exports includes audit.",
            "audit_offload",
        )
    return False, (
        f"audit_logs={value or 'disabled (default)'}; "
        f"enabled_cloudwatch_logs_exports={sorted(exports) or 'none'}; "
        "expected audit events enabled and exported to CloudWatch."
    )


def _check_encryption_at_rest(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    encrypted = get_nested(cluster, "values", "storage_encrypted", default=False)
    if truthy(encrypted):
        return True, _with_evidence(
            "storage_encrypted=true; DocumentDB storage encryption is enabled.",
            "encryption_at_rest",
        )
    return False, f"storage_encrypted={encrypted}; expected true."


def _check_cmk_encryption(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    encrypted = truthy(get_nested(cluster, "values", "storage_encrypted", default=False))
    kms_key_id = str(get_nested(cluster, "values", "kms_key_id", default="") or "")
    if encrypted and kms_key_id:
        return True, _with_evidence(
            "storage_encrypted=true and kms_key_id is a customer managed key.",
            "cmk_encryption",
        )
    return False, "storage_encrypted must be true and kms_key_id must identify a customer managed KMS key."


def _check_supported_version(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    version = str(get_nested(cluster, "values", "engine_version", default="") or "")
    major = engine_major_version(cluster)
    if major in SUPPORTED_MAJOR_VERSIONS:
        return True, _with_evidence(
            f"engine_version={version}; DocumentDB {major}.x is in standard support.",
            "supported_version",
        )
    shown = version or "not configured"
    return False, (
        f"engine_version={shown}; expected DocumentDB 4.0, 5.0, or 8.0. "
        "DocumentDB 3.6 reached EOL in March 2026."
    )


def _check_network_restrictions(cluster: dict, _related: list[dict]) -> tuple[bool, str]:
    subnet_group = str(get_nested(cluster, "values", "db_subnet_group_name", default="") or "")
    security_groups = get_nested(cluster, "values", "vpc_security_group_ids", default=[]) or []
    if subnet_group and security_groups:
        return True, _with_evidence(
            f"db_subnet_group_name={subnet_group}; vpc_security_group_ids={security_groups}.",
            "network_restrictions",
        )
    return False, "db_subnet_group_name and vpc_security_group_ids must both be configured."


CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str] | tuple[bool, str, bool]]] = {
    "tls_required": _check_tls_required,
    "fips_tls": _check_fips_tls,
    "audit_logs": _check_audit_logs,
    "audit_offload": _check_audit_offload,
    "encryption_at_rest": _check_encryption_at_rest,
    "cmk_encryption": _check_cmk_encryption,
    "supported_version": _check_supported_version,
    "network_restrictions": _check_network_restrictions,
}
CONTROL_MAPPINGS = load_control_mappings(
    CONTROL_MAPPING_DATA,
    module_name="documentdb",
    validation_functions=CHECKS,
    evidence_keys=set(EVIDENCE),
)
SEVERITY_MAP: dict[str, Severity] = {
    "CAT_I": Severity.CAT_I,
    "CAT_II": Severity.CAT_II,
    "CAT_III": Severity.CAT_III,
}


def _build_controls() -> list[StigControl]:
    controls: list[StigControl] = []
    for entry in CONTROL_DATA:
        vuln_id = str(entry["vuln_id"])
        title = str(entry["title"])
        mapping = CONTROL_MAPPINGS.for_control(vuln_id)
        if mapping.validation_function_name:
            check = CHECKS[mapping.validation_function_name]
            remediation = _remediation_comment(mapping.remediation_key) if mapping.remediation_key else ""
            csp_inherited = False
        else:
            check = make_platform_check(
                mapping,
                lambda item, _resource, _related, vuln_id=vuln_id, title=title: _platform_detail(
                    item,
                    vuln_id,
                    title,
                ),
            )
            remediation = ""
            csp_inherited = mapping.include_in_blank_cklb
        controls.append(
            StigControl(
                vuln_id=vuln_id,
                stig_id=str(entry["stig_id"]),
                severity=SEVERITY_MAP[str(entry["severity"])],
                title=title,
                description=str(entry["description"]),
                check=check,
                csp_inherited=csp_inherited,
                group_id=str(entry.get("group_id", "")),
                rule_id=str(entry.get("rule_id", "")),
                rule_version=str(entry.get("rule_version", "")),
                group_title=str(entry.get("group_title", "")),
                check_content=str(entry.get("check_content", "")),
                fix_text=str(entry.get("fix_text", "")),
                cci=tuple(str(item) for item in entry.get("cci", ())),
                false_positives=str(entry.get("false_positives", "")),
                false_negatives=str(entry.get("false_negatives", "")),
                documentable=str(entry.get("documentable", "")),
                mitigations=str(entry.get("mitigations", "")),
                potential_impacts=str(entry.get("potential_impacts", "")),
                third_party_tools=str(entry.get("third_party_tools", "")),
                mitigation_control=str(entry.get("mitigation_control", "")),
                responsibility=str(entry.get("responsibility", "")),
                security_override_guidance=str(entry.get("security_override_guidance", "")),
                check_content_ref=dict(entry.get("check_content_ref", {})),
                remediation_comment=remediation,
            ),
        )
    return controls


STIG_CONTROLS: list[StigControl] = _build_controls()


@register
class DocumentDbStigModule(BaseStigModule):
    """Amazon DocumentDB STIG compliance module."""

    name = "documentdb"
    description = "MongoDB Enterprise Advanced 8.x STIG — aws_docdb_cluster"
    resource_type = "aws_docdb_cluster"
    related_resource_types = {
        "aws_docdb_cluster_instance",
        "aws_docdb_cluster_parameter_group",
        "aws_docdb_subnet_group",
    }
    report_title = "Amazon DocumentDB STIG Report"

    stig_benchmark_id = "MongoDB_Enterprise_Advanced_8-x_STIG"
    stig_benchmark_title = "MongoDB Enterprise Advanced 8.x Security Technical Implementation Guide"
    stig_version = "1"
    stig_release_info = "Release: 1 Benchmark Date: 26 Jan 2026"

    def controls(self) -> list[StigControl]:
        """Return the DocumentDB STIG control catalogue."""
        return STIG_CONTROLS

    def find_resources(
        self, all_resources: list[dict],
    ) -> list[tuple[dict, list[dict]]]:
        """Find DocumentDB clusters and their parameter, subnet, and instance resources."""
        primaries = [
            resource
            for resource in filter_by_type(all_resources, self.resource_type)
            if str(get_nested(resource, "values", "engine", default="docdb")).lower() in {"", "docdb"}
        ]
        related = [resource for resource in all_resources if resource.get("type") in self.related_resource_types]
        result: list[tuple[dict, list[dict]]] = []
        for primary in primaries:
            parameter_group = str(get_nested(primary, "values", "db_cluster_parameter_group_name", default="") or "")
            subnet_group = str(get_nested(primary, "values", "db_subnet_group_name", default="") or "")
            identifier = str(
                get_nested(primary, "values", "cluster_identifier", default="")
                or get_nested(primary, "values", "id", default="")
            )
            matched = []
            for resource in related:
                name = str(get_nested(resource, "values", "name", default="") or "")
                if (parameter_group and name == parameter_group) or (subnet_group and name == subnet_group):
                    matched.append(resource)
                elif resource.get("type") == "aws_docdb_cluster_instance":
                    instance_cluster = str(get_nested(resource, "values", "cluster_identifier", default="") or "")
                    if identifier and instance_cluster == identifier:
                        matched.append(resource)
            result.append((primary, matched))
        return result
