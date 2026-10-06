"""Amazon RDS for MySQL checks for the MySQL 8.0 STIG."""

from __future__ import annotations

from typing import Callable

from ..models import Severity, StigControl
from ..plan_parser import filter_by_type
from ..registry import register
from ..util import get_nested
from ._aws import (
    cluster_identifier,
    cluster_instances,
    csv_tokens,
    disabled,
    engine_major_version,
    is_rds_cluster,
    load_json_file,
    option_names,
    parameter_value,
    remediation_comment,
    truthy,
    with_aws_evidence,
)
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

MYSQL_CONTROLS_FILE = "stigs/rds_mysql_controls.json"
MYSQL_CONTROL_MAPPINGS_FILE = "mappings/rds_mysql_controls.json"
MYSQL_EVIDENCE_FILE = "mappings/rds_mysql_evidence.json"

MYSQL_CONTROL_DATA: list[dict[str, object]] = list(load_json_file(MYSQL_CONTROLS_FILE))
MYSQL_CONTROL_MAPPING_DATA: dict[str, object] = dict(load_json_file(MYSQL_CONTROL_MAPPINGS_FILE))
MYSQL_EVIDENCE: dict[str, dict[str, object]] = dict(load_json_file(MYSQL_EVIDENCE_FILE))


def _with_evidence(detail: str, evidence_key: str) -> str:
    return with_aws_evidence(detail, evidence_key, MYSQL_EVIDENCE)


def _remediation_comment(evidence_key: str) -> str:
    return remediation_comment(evidence_key, MYSQL_EVIDENCE)


def _platform_detail(mapping: ControlMapping, vuln_id: str, title: str) -> str:
    return mapping.automatic_platform_text.format(vuln_id=vuln_id, title=title)


def _log_exports(server: dict) -> set[str]:
    return {str(item).lower() for item in get_nested(server, "values", "enabled_cloudwatch_logs_exports", default=[]) or []}


def _mysql_audit_events(value: object) -> set[str]:
    tokens = csv_tokens(value)
    aliases = {
        "connection": "connect",
        "ddl": "query_ddl",
        "dcl": "query_dcl",
        "dml": "query_dml",
    }
    normalized = {aliases.get(token, token) for token in tokens}
    if "query" in normalized:
        normalized.update({"query_dcl", "query_ddl", "query_dml"})
    return normalized


def _check_tls_enforced(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = parameter_value(related, "require_secure_transport")
    if truthy(value):
        return True, _with_evidence(
            f"require_secure_transport={value}; all client connections must use TLS.",
            "tls_enforced",
        )
    return False, f"require_secure_transport={value or 'not configured'}; expected ON."


def _check_tls_version(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(parameter_value(related, "tls_version", ""))
    normalized = value.lower().replace(" ", "")
    if ("tlsv1.2" in normalized or "tlsv1.3" in normalized) and "tlsv1.0" not in normalized and "tlsv1.1" not in normalized:
        return True, _with_evidence(
            f"tls_version={value}; only TLS 1.2 or newer is permitted.",
            "tls_version",
        )
    return False, f"tls_version={value or 'not configured'}; expected TLSv1.2 or TLSv1.3 only."


def _check_max_user_connections(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = parameter_value(related, "max_user_connections")
    try:
        limit = int(str(value))
    except (TypeError, ValueError):
        return False, f"max_user_connections={value or 'not configured'}; expected a positive integer."
    if limit > 0:
        return True, _with_evidence(
            f"max_user_connections={limit}; a finite per-user concurrent session limit is configured.",
            "max_user_connections",
        )
    return False, f"max_user_connections={limit}; expected a positive finite per-user session limit."


def _check_audit_log_enabled(_server: dict, related: list[dict]) -> tuple[bool, str]:
    options = option_names(related)
    if "mariadb_audit_plugin" in options:
        return True, _with_evidence(
            "MARIADB_AUDIT_PLUGIN option is configured for RDS MySQL audit logging.",
            "audit_log_enabled",
        )
    if truthy(parameter_value(related, "server_audit_logging")):
        return True, _with_evidence(
            "server_audit_logging=ON for Aurora MySQL audit logging.",
            "audit_log_enabled",
        )
    return False, "MARIADB_AUDIT_PLUGIN or server_audit_logging is not configured."


def _check_audit_log_events(_server: dict, related: list[dict]) -> tuple[bool, str]:
    options = option_names(related)
    audit_enabled = "mariadb_audit_plugin" in options or truthy(parameter_value(related, "server_audit_logging"))
    if not audit_enabled:
        return False, "Audit logging is not enabled; audit events cannot satisfy STIG audit rules."
    raw_events = parameter_value(related, "server_audit_events", "")
    events = _mysql_audit_events(raw_events)
    required = {"connect", "query_dcl", "query_ddl", "query_dml"}
    if required <= events:
        return True, _with_evidence(
            f"server_audit_events={raw_events} (normalized: {', '.join(sorted(events))}) covers required audit categories.",
            "audit_log_events",
        )
    return False, (
        f"server_audit_events={raw_events} (normalized: {', '.join(sorted(events))}) "
        f"missing: {', '.join(sorted(required - events))}."
    )


def _check_public_network_access(server: dict, related: list[dict]) -> tuple[bool, str]:
    if is_rds_cluster(server):
        public_instances = [
            instance.get("address", "unknown")
            for instance in cluster_instances(server, related)
            if truthy(get_nested(instance, "values", "publicly_accessible"))
        ]
        if not public_instances:
            return True, _with_evidence(
                "No Aurora cluster instances are publicly accessible.",
                "public_network_access",
            )
        return False, f"publicly_accessible cluster instances found: {', '.join(public_instances)}."

    value = get_nested(server, "values", "publicly_accessible")
    if disabled(value):
        return True, _with_evidence(
            "publicly_accessible=false; the DB instance has no public endpoint.",
            "public_network_access",
        )
    return False, f"publicly_accessible={value}; expected false."


def _check_subnet_group(server: dict, related: list[dict]) -> tuple[bool, str]:
    subnet_group = get_nested(server, "values", "db_subnet_group_name")
    has_related = any(resource.get("type") == "aws_db_subnet_group" for resource in related)
    if subnet_group and has_related:
        return True, _with_evidence(
            f"db_subnet_group_name={subnet_group}; the instance is placed in a VPC subnet group.",
            "subnet_group",
        )
    return False, "db_subnet_group_name or related aws_db_subnet_group evidence is missing."


def _check_security_groups(server: dict, _related: list[dict]) -> tuple[bool, str]:
    groups = get_nested(server, "values", "vpc_security_group_ids", default=[]) or []
    if groups:
        return True, _with_evidence(
            f"vpc_security_group_ids configured ({len(groups)} group(s)).",
            "security_groups",
        )
    return False, "vpc_security_group_ids is empty; no VPC security group evidence found."


def _check_backup_retention(server: dict, _related: list[dict]) -> tuple[bool, str]:
    value = get_nested(server, "values", "backup_retention_period")
    try:
        days = int(value)
    except (TypeError, ValueError):
        return False, f"backup_retention_period={value or 'not configured'}; expected at least 7."
    if days >= 7:
        return True, _with_evidence(
            f"backup_retention_period={days}; automated backups support point-in-time recovery.",
            "backup_retention",
        )
    return False, f"backup_retention_period={days}; expected at least 7."


def _check_deletion_protection(server: dict, _related: list[dict]) -> tuple[bool, str]:
    protected = get_nested(server, "values", "deletion_protection")
    skip_final = get_nested(server, "values", "skip_final_snapshot", default=False)
    if truthy(protected) and disabled(skip_final):
        return True, _with_evidence(
            "deletion_protection=true and skip_final_snapshot=false.",
            "deletion_protection",
        )
    return False, f"deletion_protection={protected}, skip_final_snapshot={skip_final}; expected true/false."


def _check_high_availability(server: dict, related: list[dict]) -> tuple[bool, str]:
    if is_rds_cluster(server):
        instances = cluster_instances(server, related)
        if len(instances) >= 2:
            return True, _with_evidence(
                f"Aurora cluster has {len(instances)} instances for cross-AZ availability.",
                "high_availability",
            )
        return False, "expected at least two aws_rds_cluster_instance resources for Aurora high availability."

    value = get_nested(server, "values", "multi_az")
    if truthy(value):
        return True, _with_evidence(
            "multi_az=true; RDS maintains a synchronous standby in another Availability Zone.",
            "high_availability",
        )
    return False, f"multi_az={value}; expected true."


def _check_cmk_encryption(server: dict, _related: list[dict]) -> tuple[bool, str]:
    encrypted = get_nested(server, "values", "storage_encrypted")
    kms_key = get_nested(server, "values", "kms_key_id")
    if truthy(encrypted) and kms_key:
        return True, _with_evidence(
            f"storage_encrypted=true with kms_key_id={kms_key}.",
            "cmk_encryption",
        )
    return False, "storage_encrypted=true with kms_key_id is required."


def _check_iam_auth(server: dict, _related: list[dict]) -> tuple[bool, str]:
    value = get_nested(server, "values", "iam_database_authentication_enabled")
    if truthy(value):
        return True, _with_evidence(
            "iam_database_authentication_enabled=true; authentication can be managed through IAM.",
            "iam_auth",
        )
    return False, f"iam_database_authentication_enabled={value}; expected true."


def _check_cloudwatch_logs(server: dict, _related: list[dict]) -> tuple[bool, str]:
    exports = _log_exports(server)
    required = {"audit", "error", "general", "slowquery"}
    if required <= exports:
        return True, _with_evidence(
            f"enabled_cloudwatch_logs_exports includes {', '.join(sorted(exports))}.",
            "cloudwatch_logs",
        )
    return False, f"enabled_cloudwatch_logs_exports missing: {', '.join(sorted(required - exports))}."


def _check_storage_autoscaling(server: dict, _related: list[dict]) -> tuple[bool, str]:
    if is_rds_cluster(server):
        return True, _with_evidence(
            "Aurora clusters automatically scale storage up to the configured maximum.",
            "storage_autoscaling",
        )

    allocated = get_nested(server, "values", "allocated_storage")
    maximum = get_nested(server, "values", "max_allocated_storage")
    try:
        allocated_int = int(allocated)
        maximum_int = int(maximum)
    except (TypeError, ValueError):
        return False, "allocated_storage and max_allocated_storage must both be numeric."
    if maximum_int > allocated_int:
        return True, _with_evidence(
            f"max_allocated_storage={maximum_int} exceeds allocated_storage={allocated_int}.",
            "storage_autoscaling",
        )
    return False, f"max_allocated_storage={maximum_int}; expected greater than allocated_storage={allocated_int}."


def _check_instance_class(server: dict, related: list[dict]) -> tuple[bool, str]:
    if is_rds_cluster(server):
        instances = cluster_instances(server, related)
        burstable = [
            instance.get("address", "unknown")
            for instance in instances
            if str(get_nested(instance, "values", "instance_class", default="")).startswith("db.t")
        ]
        if instances and not burstable:
            classes = ", ".join(
                str(get_nested(instance, "values", "instance_class", default="unknown"))
                for instance in instances
            )
            return True, _with_evidence(
                f"Aurora cluster instances use non-burstable classes: {classes}.",
                "instance_class",
            )
        if burstable:
            return False, f"burstable cluster instances found: {', '.join(burstable)}."
        return False, "no aws_rds_cluster_instance resources found for class evaluation."

    instance_class = str(get_nested(server, "values", "instance_class", default=""))
    if instance_class and not instance_class.startswith("db.t"):
        return True, _with_evidence(
            f"instance_class={instance_class}; not a burstable T-family class.",
            "instance_class",
        )
    return False, f"instance_class={instance_class or 'not configured'}; expected non-burstable production class."


def _check_version(server: dict, _related: list[dict]) -> tuple[bool, str]:
    major = engine_major_version(server)
    version = get_nested(server, "values", "engine_version", default="")
    if major and major >= 8:
        return True, _with_evidence(
            f"engine_version={version}; RDS MySQL major version is supported for this module.",
            "version",
        )
    return False, f"engine_version={version or 'not configured'}; expected MySQL 8.0 or newer."


def _check_maintenance_window(server: dict, _related: list[dict]) -> tuple[bool, str]:
    if is_rds_cluster(server):
        maintenance = get_nested(server, "values", "preferred_maintenance_window")
        backup = get_nested(server, "values", "preferred_backup_window")
        if maintenance and backup:
            return True, _with_evidence(
                f"preferred_maintenance_window={maintenance} and preferred_backup_window={backup}.",
                "maintenance_window",
            )
        return False, "preferred_maintenance_window and preferred_backup_window must both be configured."

    maintenance = get_nested(server, "values", "maintenance_window")
    backup = get_nested(server, "values", "backup_window")
    if maintenance and backup:
        return True, _with_evidence(
            f"maintenance_window={maintenance} and backup_window={backup}.",
            "maintenance_window",
        )
    return False, "maintenance_window and backup_window must both be explicitly configured."


CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str] | tuple[bool, str, bool]]] = {
    "tls_enforced": _check_tls_enforced,
    "tls_version": _check_tls_version,
    "max_user_connections": _check_max_user_connections,
    "audit_log_enabled": _check_audit_log_enabled,
    "audit_log_events": _check_audit_log_events,
    "public_network_access": _check_public_network_access,
    "subnet_group": _check_subnet_group,
    "security_groups": _check_security_groups,
    "backup_retention": _check_backup_retention,
    "deletion_protection": _check_deletion_protection,
    "high_availability": _check_high_availability,
    "cmk_encryption": _check_cmk_encryption,
    "iam_auth": _check_iam_auth,
    "cloudwatch_logs": _check_cloudwatch_logs,
    "storage_autoscaling": _check_storage_autoscaling,
    "instance_class": _check_instance_class,
    "version": _check_version,
    "maintenance_window": _check_maintenance_window,
}
MYSQL_CONTROL_MAPPINGS = load_control_mappings(
    MYSQL_CONTROL_MAPPING_DATA,
    module_name="rds_mysql",
    validation_functions=CHECKS,
    evidence_keys=set(MYSQL_EVIDENCE),
)
SEVERITY_MAP: dict[str, Severity] = {
    "CAT_I": Severity.CAT_I,
    "CAT_II": Severity.CAT_II,
    "CAT_III": Severity.CAT_III,
}


def _build_controls() -> list[StigControl]:
    controls = []
    for entry in MYSQL_CONTROL_DATA:
        vuln_id = str(entry["vuln_id"])
        title = str(entry["title"])
        mapping = MYSQL_CONTROL_MAPPINGS.for_control(vuln_id)
        if mapping.validation_function_name:
            check = CHECKS[mapping.validation_function_name]
            remediation = _remediation_comment(mapping.remediation_key) if mapping.remediation_key else ""
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
        controls.append(
            StigControl(
                vuln_id=vuln_id,
                stig_id=str(entry["stig_id"]),
                severity=SEVERITY_MAP[str(entry["severity"])],
                title=title,
                description=str(entry["description"]),
                check=check,
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
class RdsMysqlStigModule(BaseStigModule):
    """Amazon RDS for MySQL STIG compliance module."""

    name = "rds_mysql"
    description = "Oracle MySQL 8.0 STIG — aws_db_instance / aws_rds_cluster (RDS/Aurora MySQL)"
    resource_type = "aws_db_instance"
    additional_resource_types = {"aws_rds_cluster"}
    related_resource_types = {
        "aws_db_option_group",
        "aws_db_parameter_group",
        "aws_db_subnet_group",
        "aws_rds_cluster_instance",
        "aws_rds_cluster_option_group",
        "aws_rds_cluster_parameter_group",
    }
    report_title = "Amazon RDS MySQL STIG Report"

    stig_benchmark_id = "Oracle_MySQL_8.0_STIG"
    stig_benchmark_title = "Oracle MySQL 8.0 Security Technical Implementation Guide"
    stig_version = "2"
    stig_release_info = "Release: 2 Benchmark Date: 24 Oct 2024"

    def controls(self) -> list[StigControl]:
        """Return the RDS MySQL STIG control catalogue."""
        return STIG_CONTROLS

    def find_resources(self, all_resources: list[dict]) -> list[tuple[dict, list[dict]]]:
        """Find RDS MySQL instances, Aurora clusters, and matching parameter/option/subnet groups."""
        instances = [
            resource
            for resource in filter_by_type(all_resources, self.resource_type)
            if str(get_nested(resource, "values", "engine", default="")).lower() == "mysql"
        ]
        clusters = [
            resource
            for resource in filter_by_type(all_resources, "aws_rds_cluster")
            if "mysql" in str(get_nested(resource, "values", "engine", default="")).lower()
        ]
        related = [resource for resource in all_resources if resource.get("type") in self.related_resource_types]

        result = []
        for primary in instances + clusters:
            parameter_group = get_nested(
                primary,
                "values",
                "parameter_group_name" if not is_rds_cluster(primary) else "db_cluster_parameter_group_name",
                default="",
            )
            option_group = get_nested(
                primary,
                "values",
                "option_group_name" if not is_rds_cluster(primary) else "db_cluster_option_group_name",
                default="",
            )
            subnet_group = get_nested(primary, "values", "db_subnet_group_name", default="")
            identifier = cluster_identifier(primary) if is_rds_cluster(primary) else ""
            matched = []
            for resource in related:
                name = get_nested(resource, "values", "name", default="")
                if (
                    (parameter_group and name == parameter_group)
                    or (option_group and name == option_group)
                    or (subnet_group and name == subnet_group)
                ):
                    matched.append(resource)
                elif is_rds_cluster(primary) and resource.get("type") == "aws_rds_cluster_instance":
                    if str(get_nested(resource, "values", "cluster_identifier", default="")) == identifier:
                        matched.append(resource)
            result.append((primary, matched))
        return result
