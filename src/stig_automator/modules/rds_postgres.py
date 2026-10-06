"""Amazon RDS for PostgreSQL checks for the Crunchy Data Postgres 16 STIG."""

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
    parameter_value,
    remediation_comment,
    truthy,
    with_aws_evidence,
)
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

POSTGRES_CONTROLS_FILE = "stigs/rds_postgres_controls.json"
POSTGRES_CONTROL_MAPPINGS_FILE = "mappings/rds_postgres_controls.json"
POSTGRES_EVIDENCE_FILE = "mappings/rds_postgres_evidence.json"

POSTGRES_CONTROL_DATA: list[dict[str, object]] = list(load_json_file(POSTGRES_CONTROLS_FILE))
POSTGRES_CONTROL_MAPPING_DATA: dict[str, object] = dict(load_json_file(POSTGRES_CONTROL_MAPPINGS_FILE))
POSTGRES_EVIDENCE: dict[str, dict[str, object]] = dict(load_json_file(POSTGRES_EVIDENCE_FILE))


def _with_evidence(detail: str, evidence_key: str) -> str:
    return with_aws_evidence(detail, evidence_key, POSTGRES_EVIDENCE)


def _remediation_comment(evidence_key: str) -> str:
    return remediation_comment(evidence_key, POSTGRES_EVIDENCE)


def _platform_detail(mapping: ControlMapping, vuln_id: str, title: str) -> str:
    detail = mapping.automatic_platform_text.format(vuln_id=vuln_id, title=title)
    if not mapping.evidence_key:
        return detail
    evidence = POSTGRES_EVIDENCE[mapping.evidence_key]
    quote = str(evidence["quote"])
    url = str(evidence["url"])
    if mapping.include_in_blank_cklb:
        return f'AWS documentation evidence: "{quote}" ({url}) Inherited CSP/baseline controls: {detail}'
    return f'AWS documentation evidence: "{quote}" ({url}) {detail}'


def _log_exports(server: dict) -> set[str]:
    return {str(item).lower() for item in get_nested(server, "values", "enabled_cloudwatch_logs_exports", default=[]) or []}


def _force_ssl(related: list[dict]) -> bool:
    return truthy(parameter_value(related, "rds.force_ssl"))


def _pgaudit_enabled(related: list[dict]) -> bool:
    libraries = csv_tokens(parameter_value(related, "shared_preload_libraries", ""))
    return "pgaudit" in libraries


def _pgaudit_log_classes(related: list[dict]) -> set[str]:
    tokens = csv_tokens(parameter_value(related, "pgaudit.log", ""))
    if "all" in tokens:
        return {"read", "write", "ddl", "role", "function", "misc"}
    return {token.lstrip("-") for token in tokens if not token.startswith("-")}


def _log_line_prefix(related: list[dict]) -> str:
    return str(parameter_value(related, "log_line_prefix", ""))


def _positive_duration(value: object) -> bool:
    text = str(value or "").strip().lower()
    digits = ""
    for char in text:
        if char.isdigit() or char == ".":
            digits += char
        else:
            break
    if not digits:
        return False
    try:
        return float(digits) > 0
    except ValueError:
        return False


def _check_supported_version(server: dict, _related: list[dict]) -> tuple[bool, str]:
    major = engine_major_version(server)
    version = get_nested(server, "values", "engine_version", default="")
    if major and major >= 16:
        return True, _with_evidence(
            f"engine_version={version}; RDS PostgreSQL major version aligns with the Postgres 16 STIG target.",
            "supported_version",
        )
    return False, f"engine_version={version or 'not configured'}; expected PostgreSQL 16 or newer."


def _check_enterprise_auth(server: dict, _related: list[dict]) -> tuple[bool, str]:
    value = get_nested(server, "values", "iam_database_authentication_enabled")
    if truthy(value):
        return True, _with_evidence(
            "iam_database_authentication_enabled=true; authentication can be centralized with IAM.",
            "enterprise_auth",
        )
    return False, f"iam_database_authentication_enabled={value}; expected true."


def _check_authorization_policy(server: dict, _related: list[dict]) -> tuple[bool, str]:
    value = get_nested(server, "values", "iam_database_authentication_enabled")
    if truthy(value):
        return True, _with_evidence(
            "IAM database authentication is enabled for approved logical access enforcement.",
            "authorization_policy",
        )
    return False, "IAM database authentication is not enabled for this RDS PostgreSQL instance."


def _check_password_hashing(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(parameter_value(related, "password_encryption", "")).lower()
    if value == "scram-sha-256":
        return True, _with_evidence(
            "password_encryption=scram-sha-256.",
            "password_hashing",
        )
    return False, f"password_encryption={value or 'not configured'}; expected scram-sha-256."


def _check_password_transmission(_server: dict, related: list[dict]) -> tuple[bool, str]:
    if _force_ssl(related):
        return True, _with_evidence(
            "rds.force_ssl=1; PostgreSQL clients must use SSL/TLS.",
            "password_transmission",
        )
    return False, "rds.force_ssl is not enabled."


def _check_at_rest_cmk(server: dict, _related: list[dict]) -> tuple[bool, str]:
    encrypted = get_nested(server, "values", "storage_encrypted")
    kms_key = get_nested(server, "values", "kms_key_id")
    if truthy(encrypted) and kms_key:
        return True, _with_evidence(
            f"storage_encrypted=true with kms_key_id={kms_key}.",
            "at_rest_cmk",
        )
    return False, "storage_encrypted=true with kms_key_id is required."


def _check_max_connections(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = parameter_value(related, "max_connections")
    try:
        limit = int(str(value))
    except (TypeError, ValueError):
        return False, f"max_connections={value or 'not configured'}; expected a positive integer."
    if limit > 0:
        return True, _with_evidence(
            f"max_connections={limit}; a finite connection ceiling is configured.",
            "max_connections",
        )
    return False, f"max_connections={limit}; expected a positive integer."


def _check_pgaudit_events(_server: dict, related: list[dict]) -> tuple[bool, str]:
    classes = _pgaudit_log_classes(related)
    required = {"read", "write", "ddl", "role"}
    if _pgaudit_enabled(related) and required <= classes:
        return True, _with_evidence(
            f"pgaudit.log covers {', '.join(sorted(classes))}.",
            "pgaudit_events",
        )
    if not _pgaudit_enabled(related):
        return False, "shared_preload_libraries does not include pgaudit."
    return False, f"pgaudit.log missing: {', '.join(sorted(required - classes))}."


def _check_session_auditing_startup(_server: dict, related: list[dict]) -> tuple[bool, str]:
    destination = str(parameter_value(related, "log_destination", "")).lower()
    if _pgaudit_enabled(related) and ("stderr" in destination or "csvlog" in destination):
        return True, _with_evidence(
            f"pgaudit is enabled and log_destination={destination}.",
            "session_auditing_startup",
        )
    return False, "pgaudit and log_destination=stderr or csvlog are not both configured."


def _check_audit_event_content(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    required_prefix = {"%m", "%u", "%d", "%c"}
    missing = {token for token in required_prefix if token not in prefix}
    if not truthy(parameter_value(related, "log_connections")) or not truthy(parameter_value(related, "log_disconnections")):
        return False, "log_connections and log_disconnections must both be on."
    if missing:
        return False, f"log_line_prefix missing: {', '.join(sorted(missing))}."
    return True, _with_evidence(
        "log_connections=on, log_disconnections=on, and log_line_prefix captures event context.",
        "audit_event_content",
    )


def _check_audit_timestamps(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    if "%m" in prefix:
        return True, _with_evidence(
            f"log_line_prefix={prefix} includes timestamps.",
            "audit_timestamps",
        )
    return False, "log_line_prefix does not include %m."


def _check_audit_identity(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    required = {"%m", "%u", "%d", "%p", "%r", "%a"}
    missing = {token for token in required if token not in prefix}
    if not missing:
        return True, _with_evidence(
            "log_line_prefix includes timestamp, user, database, process, remote host, and application.",
            "audit_identity",
        )
    return False, f"log_line_prefix missing: {', '.join(sorted(missing))}."


def _check_network_restrictions(server: dict, related: list[dict]) -> tuple[bool, str]:
    if is_rds_cluster(server):
        groups = get_nested(server, "values", "vpc_security_group_ids", default=[]) or []
        subnet_group = get_nested(server, "values", "db_subnet_group_name")
        public_instances = [
            instance.get("address", "unknown")
            for instance in cluster_instances(server, related)
            if truthy(get_nested(instance, "values", "publicly_accessible"))
        ]
        if groups and subnet_group and not public_instances:
            return True, _with_evidence(
                "Aurora cluster has VPC security groups and DB subnet group configured with no publicly accessible instances.",
                "network_restrictions",
            )
        if public_instances:
            return False, f"publicly_accessible cluster instances found: {', '.join(public_instances)}."
        return False, "expected vpc_security_group_ids and db_subnet_group_name on the Aurora cluster."

    public = get_nested(server, "values", "publicly_accessible")
    groups = get_nested(server, "values", "vpc_security_group_ids", default=[]) or []
    subnet_group = get_nested(server, "values", "db_subnet_group_name")
    if disabled(public) and groups and subnet_group:
        return True, _with_evidence(
            "publicly_accessible=false with VPC security groups and DB subnet group configured.",
            "network_restrictions",
        )
    return False, "expected publicly_accessible=false with vpc_security_group_ids and db_subnet_group_name."


def _check_centralized_logs(server: dict, _related: list[dict]) -> tuple[bool, str]:
    exports = _log_exports(server)
    if "postgresql" in exports:
        return True, _with_evidence(
            f"enabled_cloudwatch_logs_exports includes {', '.join(sorted(exports))}.",
            "centralized_logs",
        )
    return False, "enabled_cloudwatch_logs_exports does not include postgresql."


def _check_log_timezone(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(parameter_value(related, "log_timezone", "")).upper()
    if value == "UTC":
        return True, _with_evidence("log_timezone=UTC.", "log_timezone")
    return False, f"log_timezone={value or 'not configured'}; expected UTC."


def _check_timestamp_granularity(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    if "%m" in prefix:
        return True, _with_evidence(
            "log_line_prefix uses %m, which records millisecond timestamps.",
            "timestamp_granularity",
        )
    return False, "log_line_prefix does not use %m."


def _check_approved_ca_tls(server: dict, related: list[dict]) -> tuple[bool, str]:
    if is_rds_cluster(server):
        instances = cluster_instances(server, related)
        if instances:
            missing_ca = [
                instance.get("address", "unknown")
                for instance in instances
                if not get_nested(instance, "values", "ca_cert_identifier")
            ]
            if _force_ssl(related) and not missing_ca:
                return True, _with_evidence(
                    "rds.force_ssl=1 and all Aurora cluster instances specify ca_cert_identifier.",
                    "approved_ca_tls",
                )
            if missing_ca:
                return False, f"cluster instances missing ca_cert_identifier: {', '.join(missing_ca)}."
        return False, "rds.force_ssl and ca_cert_identifier must both be configured for Aurora cluster instances."

    ca = get_nested(server, "values", "ca_cert_identifier")
    if _force_ssl(related) and ca:
        return True, _with_evidence(
            f"rds.force_ssl=1 and ca_cert_identifier={ca}.",
            "approved_ca_tls",
        )
    return False, "rds.force_ssl and ca_cert_identifier must both be configured."


def _check_audit_event_location(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    required = {"%m", "%u", "%d", "%s"}
    missing = {token for token in required if token not in prefix}
    if not missing:
        return True, _with_evidence(
            f"log_line_prefix={prefix} includes timestamp, user, database, and process-start fields.",
            "audit_event_location",
        )
    return False, f"log_line_prefix is missing location fields: {', '.join(sorted(missing))}."


def _check_audit_event_source(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    if not truthy(parameter_value(related, "log_hostname")):
        return False, "log_hostname is not enabled."
    if "%h" not in prefix and "%r" not in prefix:
        return False, "log_line_prefix does not include %h or %r source fields."
    return True, _with_evidence(
        "log_hostname=on and log_line_prefix captures the connection source.",
        "audit_event_source",
    )


def _check_audit_event_outcome(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(parameter_value(related, "log_error_verbosity", "")).lower()
    if value == "verbose":
        return True, _with_evidence("log_error_verbosity=verbose.", "audit_event_outcome")
    return False, f"log_error_verbosity={value or 'not configured'}; expected verbose."


def _check_client_error_messages(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(parameter_value(related, "client_min_messages", "")).lower()
    if value == "error":
        return True, _with_evidence("client_min_messages=error.", "client_error_messages")
    return False, f"client_min_messages={value or 'not configured'}; expected error."


def _check_session_timeout(_server: dict, related: list[dict]) -> tuple[bool, str]:
    idle_session = parameter_value(related, "idle_session_timeout")
    idle_in_transaction = parameter_value(related, "idle_in_transaction_session_timeout")
    statement = parameter_value(related, "statement_timeout")
    configured = []
    if _positive_duration(idle_session):
        configured.append(f"idle_session_timeout={idle_session}")
    if _positive_duration(idle_in_transaction):
        configured.append(f"idle_in_transaction_session_timeout={idle_in_transaction}")
    if _positive_duration(statement):
        configured.append(f"statement_timeout={statement}")
    if configured:
        return True, _with_evidence(
            "; ".join(configured) + "; a finite session/statement timeout is configured.",
            "session_timeout",
        )
    return False, (
        "idle_session_timeout, idle_in_transaction_session_timeout, or "
        "statement_timeout must be a positive duration."
    )


CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str]]] = {
    "supported_version": _check_supported_version,
    "enterprise_auth": _check_enterprise_auth,
    "authorization_policy": _check_authorization_policy,
    "password_hashing": _check_password_hashing,
    "password_transmission": _check_password_transmission,
    "at_rest_cmk": _check_at_rest_cmk,
    "max_connections": _check_max_connections,
    "pgaudit_events": _check_pgaudit_events,
    "session_auditing_startup": _check_session_auditing_startup,
    "audit_event_content": _check_audit_event_content,
    "audit_timestamps": _check_audit_timestamps,
    "audit_identity": _check_audit_identity,
    "network_restrictions": _check_network_restrictions,
    "centralized_logs": _check_centralized_logs,
    "log_timezone": _check_log_timezone,
    "timestamp_granularity": _check_timestamp_granularity,
    "approved_ca_tls": _check_approved_ca_tls,
    "audit_event_location": _check_audit_event_location,
    "audit_event_source": _check_audit_event_source,
    "audit_event_outcome": _check_audit_event_outcome,
    "client_error_messages": _check_client_error_messages,
    "session_timeout": _check_session_timeout,
}
POSTGRES_CONTROL_MAPPINGS = load_control_mappings(
    POSTGRES_CONTROL_MAPPING_DATA,
    module_name="rds_postgres",
    validation_functions=CHECKS,
    evidence_keys=set(POSTGRES_EVIDENCE),
)
SEVERITY_MAP: dict[str, Severity] = {
    "CAT_I": Severity.CAT_I,
    "CAT_II": Severity.CAT_II,
    "CAT_III": Severity.CAT_III,
}


def _build_controls() -> list[StigControl]:
    controls: list[StigControl] = []
    for entry in POSTGRES_CONTROL_DATA:
        vuln_id = str(entry["vuln_id"])
        title = str(entry["title"])
        mapping = POSTGRES_CONTROL_MAPPINGS.for_control(vuln_id)
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
class RdsPostgresStigModule(BaseStigModule):
    """Amazon RDS for PostgreSQL STIG compliance module."""

    name = "rds_postgres"
    description = "Crunchy Data Postgres 16 STIG — aws_db_instance / aws_rds_cluster (RDS/Aurora PostgreSQL)"
    resource_type = "aws_db_instance"
    additional_resource_types = {"aws_rds_cluster"}
    related_resource_types = {
        "aws_db_parameter_group",
        "aws_db_subnet_group",
        "aws_rds_cluster_instance",
        "aws_rds_cluster_parameter_group",
    }
    report_title = "Amazon RDS PostgreSQL STIG Report"

    stig_benchmark_id = "CD_Postgres_16_STIG"
    stig_benchmark_title = "Crunchy Data Postgres 16 Security Technical Implementation Guide"
    stig_version = "1"
    stig_release_info = "Release: 2 Benchmark Date: 01 Apr 2026"

    def controls(self) -> list[StigControl]:
        """Return the RDS PostgreSQL STIG control catalogue."""
        return STIG_CONTROLS

    def find_resources(self, all_resources: list[dict]) -> list[tuple[dict, list[dict]]]:
        """Find RDS PostgreSQL instances, Aurora clusters, and matching parameter/subnet groups."""
        instances = [
            resource
            for resource in filter_by_type(all_resources, self.resource_type)
            if str(get_nested(resource, "values", "engine", default="")).lower() == "postgres"
        ]
        clusters = [
            resource
            for resource in filter_by_type(all_resources, "aws_rds_cluster")
            if "postgres" in str(get_nested(resource, "values", "engine", default="")).lower()
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
            subnet_group = get_nested(primary, "values", "db_subnet_group_name", default="")
            identifier = cluster_identifier(primary) if is_rds_cluster(primary) else ""
            matched = []
            for resource in related:
                name = get_nested(resource, "values", "name", default="")
                if (parameter_group and name == parameter_group) or (subnet_group and name == subnet_group):
                    matched.append(resource)
                elif is_rds_cluster(primary) and resource.get("type") == "aws_rds_cluster_instance":
                    if str(get_nested(resource, "values", "cluster_identifier", default="")) == identifier:
                        matched.append(resource)
            result.append((primary, matched))
        return result
