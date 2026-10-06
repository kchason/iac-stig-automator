"""Azure PostgreSQL Flexible Server checks for Crunchy Data Postgres 16 STIG."""

from __future__ import annotations

import json
from importlib import resources
from typing import Callable

from ..models import Severity, StigControl
from ..plan_parser import filter_by_type
from ..registry import register
from ..util import first_nested, get_nested
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

POSTGRES_CONTROLS_FILE = "stigs/postgres_flexible_controls.json"
POSTGRES_CONTROL_MAPPINGS_FILE = "mappings/postgres_flexible_controls.json"
POSTGRES_EVIDENCE_FILE = "mappings/postgres_flexible_evidence.json"


def _load_json_file(filename: str) -> object:
    with resources.files(__package__).joinpath(filename).open(encoding="utf-8") as f:
        return json.load(f)


POSTGRES_CONTROL_DATA: list[dict[str, object]] = list(_load_json_file(POSTGRES_CONTROLS_FILE))
POSTGRES_CONTROL_MAPPING_DATA: dict[str, object] = dict(_load_json_file(POSTGRES_CONTROL_MAPPINGS_FILE))
POSTGRES_EVIDENCE: dict[str, dict[str, object]] = dict(_load_json_file(POSTGRES_EVIDENCE_FILE))


def _with_microsoft_learn_evidence(detail: str, evidence_key: str) -> str:
    evidence = POSTGRES_EVIDENCE[evidence_key]
    quote = str(evidence["quote"])
    url = str(evidence["url"])
    terraform_urls = [str(url) for url in evidence.get("terraform_urls", [])]
    properties = [str(prop) for prop in evidence.get("terraform_properties", [])]
    rdbms_urls = [str(url) for url in evidence.get("rdbms_urls", [])]
    terraform_properties = ""
    if properties:
        terraform_properties = f" Terraform properties addressed: {'; '.join(properties)}."
    terraform_docs = ""
    if terraform_urls:
        terraform_docs = f" Terraform provider docs: {', '.join(terraform_urls)}"
    rdbms_docs = ""
    if rdbms_urls:
        rdbms_docs = f" RDBMS docs: {', '.join(rdbms_urls)}"
    return f'{detail} Microsoft Learn evidence: "{quote}" ({url}){terraform_properties}{terraform_docs}{rdbms_docs}'


def _remediation_comment(evidence_key: str) -> str:
    evidence = POSTGRES_EVIDENCE[evidence_key]
    terraform_urls = [str(url) for url in evidence.get("terraform_urls", [])]
    rdbms_urls = [str(url) for url in evidence.get("rdbms_urls", [])]
    properties = [str(prop) for prop in evidence.get("terraform_properties", [])]
    if not terraform_urls or not properties:
        return ""
    rdbms_docs = ""
    if rdbms_urls:
        rdbms_docs = f" RDBMS docs: {', '.join(rdbms_urls)}"
    return (
        "Terraform remediation: configure "
        f"{'; '.join(properties)}. Provider docs: {', '.join(terraform_urls)}{rdbms_docs}"
    )


def _platform_detail(mapping: ControlMapping, vuln_id: str, title: str) -> str:
    detail = mapping.automatic_platform_text.format(vuln_id=vuln_id, title=title)
    if not mapping.evidence_key:
        return detail
    evidence = POSTGRES_EVIDENCE[mapping.evidence_key]
    quote = str(evidence["quote"])
    url = str(evidence["url"])
    if mapping.include_in_blank_cklb:
        return f'Microsoft Learn evidence: "{quote}" ({url}) Inherited CSP/baseline controls: {detail}'
    return f'Microsoft Learn evidence: "{quote}" ({url}) {detail}'


def _truthy(value: object) -> bool:
    return value is True or str(value).strip().lower() in {"1", "on", "true", "enabled", "yes"}


def _disabled(value: object) -> bool:
    return value is False or str(value).strip().lower() in {"0", "off", "false", "disabled", "no"}


def _param(related: list[dict], name: str) -> dict | None:
    for resource in related:
        if resource.get("type") != "azurerm_postgresql_flexible_server_configuration":
            continue
        if str(get_nested(resource, "values", "name", default="")).lower() == name.lower():
            return resource
    return None


def _param_value(related: list[dict], name: str, default: object = None) -> object:
    config = _param(related, name)
    if not config:
        return default
    return get_nested(config, "values", "value", default=default)


def _csv_tokens(value: object) -> set[str]:
    return {
        token.strip().strip("'\"").lower()
        for token in str(value or "").replace(";", ",").split(",")
        if token.strip()
    }


def _contains_token(value: object, token: str) -> bool:
    return token.lower() in _csv_tokens(value)


def _auth_block(server: dict) -> dict:
    return first_nested(server, "values", "authentication") or {}


def _ad_auth_enabled(server: dict, related: list[dict]) -> bool:
    auth = _auth_block(server)
    if _truthy(get_nested(auth, "active_directory_auth_enabled")):
        return True
    for resource in related:
        if resource.get("type") == "azurerm_postgresql_flexible_server_active_directory_administrator":
            return True
    return False


def _password_auth_disabled(server: dict) -> bool:
    auth = _auth_block(server)
    value = get_nested(auth, "password_auth_enabled")
    return value is not None and _disabled(value)


def _tls_min_version(server: dict, related: list[dict]) -> str:
    value = get_nested(server, "values", "ssl_minimal_tls_version_enforced")
    if not value:
        value = _param_value(related, "ssl_min_protocol_version", "")
    return str(value or "")


def _tls_is_modern(server: dict, related: list[dict]) -> bool:
    version = _tls_min_version(server, related).lower().replace("_", "").replace(".", "")
    return "tls12" in version or "tls13" in version or "tlsv12" in version or "tlsv13" in version


def _secure_transport_required(server: dict, related: list[dict]) -> bool:
    direct = get_nested(server, "values", "require_secure_transport")
    if direct is not None:
        return _truthy(direct)
    return _truthy(_param_value(related, "require_secure_transport", ""))


def _pgaudit_extension_enabled(related: list[dict]) -> bool:
    extensions = _param_value(related, "azure.extensions", "")
    preload = _param_value(related, "shared_preload_libraries", "")
    return _contains_token(extensions, "pgaudit") or _contains_token(preload, "pgaudit")


def _pgaudit_log_classes(related: list[dict]) -> set[str]:
    value = _param_value(related, "pgaudit.log", "")
    tokens = _csv_tokens(value)
    if "all" in tokens:
        return {"read", "write", "ddl", "role", "function", "misc"}
    return {token.lstrip("-") for token in tokens if not token.startswith("-")}


def _log_line_prefix(related: list[dict]) -> str:
    return str(_param_value(related, "log_line_prefix", ""))


def _config_is_on(related: list[dict], name: str) -> bool:
    return _truthy(_param_value(related, name, ""))


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


def _matching_diagnostic_settings(server: dict, related: list[dict]) -> list[dict]:
    server_id = get_nested(server, "values", "id", default="")
    settings = []
    for resource in related:
        if resource.get("type") != "azurerm_monitor_diagnostic_setting":
            continue
        target_id = get_nested(resource, "values", "target_resource_id", default="")
        if not server_id or target_id == server_id:
            settings.append(resource)
    return settings


def _diag_exports_postgres_logs(setting: dict) -> bool:
    for key in ("enabled_log", "log"):
        for log in get_nested(setting, "values", key, default=[]) or []:
            category = str(get_nested(log, "category", default="")).lower()
            category_group = str(get_nested(log, "category_group", default="")).lower()
            enabled = get_nested(log, "enabled", default=True)
            if _disabled(enabled):
                continue
            if category in {"postgresqllogs", "postgresqlflexibleserverlogs"}:
                return True
            if category_group in {"alllogs", "audit"}:
                return True
    return False


def _check_enterprise_auth(server: dict, related: list[dict]) -> tuple[bool, str]:
    if _ad_auth_enabled(server, related):
        return True, _with_microsoft_learn_evidence(
            "Active Directory authentication is enabled for organization-level account management.",
            "enterprise_auth",
        )
    return False, "Active Directory authentication is not enabled for this PostgreSQL flexible server."


def _check_authorization_policy(server: dict, related: list[dict]) -> tuple[bool, str]:
    if _ad_auth_enabled(server, related) and _password_auth_disabled(server):
        return True, _with_microsoft_learn_evidence(
            "Active Directory authentication is enabled and password authentication is disabled.",
            "authorization_policy",
        )
    if _ad_auth_enabled(server, related):
        return False, "Active Directory authentication is enabled, but password_auth_enabled is not false."
    return False, "No Active Directory authentication evidence found for enforcing centralized authorization."


def _check_password_hashing(server: dict, related: list[dict]) -> tuple[bool, str]:
    if _password_auth_disabled(server):
        return True, _with_microsoft_learn_evidence(
            "password_auth_enabled=false; database password authentication is not used.",
            "password_auth_disabled",
        )
    value = str(_param_value(related, "password_encryption", "")).lower()
    if value == "scram-sha-256":
        return True, _with_microsoft_learn_evidence(
            "password_encryption=scram-sha-256.",
            "password_hashing_scram",
        )
    return False, f"password_encryption={value or 'not configured'}; expected scram-sha-256."


def _check_password_transmission(server: dict, related: list[dict]) -> tuple[bool, str]:
    if _secure_transport_required(server, related) and _tls_is_modern(server, related):
        version = _tls_min_version(server, related)
        return True, _with_microsoft_learn_evidence(
            f"require_secure_transport=ON and minimum TLS version is {version}.",
            "password_transmission",
        )
    return False, "require_secure_transport and a TLS 1.2+ minimum version are not both configured."


def _check_at_rest_cmk(server: dict, _related: list[dict]) -> tuple[bool, str]:
    cmk = first_nested(server, "values", "customer_managed_key")
    key_id = get_nested(cmk, "key_vault_key_id") if cmk else None
    identity = first_nested(server, "values", "identity")
    identity_type = get_nested(identity, "type", default="") if identity else ""
    if key_id and identity_type:
        return True, _with_microsoft_learn_evidence(
            f"customer_managed_key.key_vault_key_id={key_id} with identity.type={identity_type}.",
            "at_rest_cmk",
        )
    if key_id:
        return False, "customer_managed_key is configured but no managed identity is attached."
    return False, "customer_managed_key is not configured for Azure-managed PostgreSQL storage encryption."


# Microsoft-supported PostgreSQL major versions for Azure Database for PostgreSQL Flexible Server.
_AZURE_FLEXIBLE_SUPPORTED_MAJORS: frozenset[int] = frozenset({11, 12, 13, 14, 15, 16, 17})


def _azure_version_major(version: str) -> int | None:
    text = str(version or "").strip()
    if not text:
        return None
    try:
        return int(text.split(".")[0])
    except ValueError:
        return None


def _check_supported_version(server: dict, _related: list[dict]) -> tuple[bool, str]:
    version = str(get_nested(server, "values", "version", default=""))
    major = _azure_version_major(version)
    if major is not None and major in _AZURE_FLEXIBLE_SUPPORTED_MAJORS:
        return True, _with_microsoft_learn_evidence(
            f"version={version}; PostgreSQL major {major} is supported by Azure Database for PostgreSQL "
            "Flexible Server.",
            "supported_version",
        )
    supported = ", ".join(str(item) for item in sorted(_AZURE_FLEXIBLE_SUPPORTED_MAJORS))
    return False, (
        f"version={version or 'not configured'}; expected an Azure-supported PostgreSQL major "
        f"({supported})."
    )


def _check_managed_security_updates(server: dict, _related: list[dict]) -> tuple[bool, str]:
    version = str(get_nested(server, "values", "version", default=""))
    major = _azure_version_major(version)
    if major is not None and major in _AZURE_FLEXIBLE_SUPPORTED_MAJORS:
        return True, _with_microsoft_learn_evidence(
            f"version={version}; on a supported major, Azure Flexible Server applies minor and security "
            "updates during platform maintenance.",
            "managed_security_updates",
        )
    supported = ", ".join(str(item) for item in sorted(_AZURE_FLEXIBLE_SUPPORTED_MAJORS))
    return False, (
        f"version={version or 'not configured'}; security updates require an Azure-supported PostgreSQL "
        f"major ({supported})."
    )


def _check_max_connections(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = _param_value(related, "max_connections")
    if value is None:
        return False, "max_connections is not explicitly configured."
    try:
        limit = int(str(value))
    except ValueError:
        return False, f"max_connections={value}; unable to parse numeric limit."
    if limit > 0:
        return True, _with_microsoft_learn_evidence(
            f"max_connections={limit}; a finite connection ceiling is configured.",
            "max_connections",
        )
    return False, f"max_connections={limit}; expected a positive finite limit."


def _check_pgaudit_events(_server: dict, related: list[dict]) -> tuple[bool, str]:
    classes = _pgaudit_log_classes(related)
    required = {"read", "write", "ddl", "role"}
    missing = required - classes
    if _pgaudit_extension_enabled(related) and not missing:
        return True, _with_microsoft_learn_evidence(
            f"pgaudit.log covers {', '.join(sorted(classes))}.",
            "pgaudit_events",
        )
    if not _pgaudit_extension_enabled(related):
        return False, "pgaudit is not enabled through azure.extensions or shared_preload_libraries."
    return False, f"pgaudit.log is missing required classes: {', '.join(sorted(missing))}."


def _check_session_auditing_startup(_server: dict, related: list[dict]) -> tuple[bool, str]:
    destination = str(_param_value(related, "log_destination", "")).lower()
    if _pgaudit_extension_enabled(related) and ("stderr" in destination or "syslog" in destination):
        return True, _with_microsoft_learn_evidence(
            f"pgaudit is enabled and log_destination={destination}.",
            "session_auditing_startup",
        )
    return False, "pgaudit and log_destination=stderr or syslog are not both configured."


def _check_audit_event_content(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    required_prefix = {"%m", "%u", "%d", "%c"}
    missing = {token for token in required_prefix if token not in prefix}
    if not _config_is_on(related, "log_connections") or not _config_is_on(related, "log_disconnections"):
        return False, "log_connections and log_disconnections must both be on."
    if missing:
        return False, f"log_line_prefix is missing required fields: {', '.join(sorted(missing))}."
    return True, _with_microsoft_learn_evidence(
        "log_connections=on, log_disconnections=on, and log_line_prefix captures event context.",
        "audit_event_content",
    )


def _check_audit_timestamps(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    if "%m" in prefix:
        return True, _with_microsoft_learn_evidence(
            f"log_line_prefix={prefix} includes millisecond timestamps.",
            "audit_timestamps",
        )
    return False, "log_line_prefix does not include %m timestamp field."


def _check_audit_identity(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    required = {"%m", "%u", "%d", "%p", "%r", "%a"}
    missing = {token for token in required if token not in prefix}
    if not missing:
        return True, _with_microsoft_learn_evidence(
            "log_line_prefix includes timestamp, user, database, process, remote host, and application.",
            "audit_identity",
        )
    return False, f"log_line_prefix is missing identity fields: {', '.join(sorted(missing))}."


def _check_network_restrictions(server: dict, related: list[dict]) -> tuple[bool, str]:
    public_access = get_nested(server, "values", "public_network_access_enabled")
    delegated_subnet = get_nested(server, "values", "delegated_subnet_id")
    private_dns = get_nested(server, "values", "private_dns_zone_id")
    wide_open_rules = []
    for resource in related:
        if resource.get("type") != "azurerm_postgresql_flexible_server_firewall_rule":
            continue
        start_ip = get_nested(resource, "values", "start_ip_address", default="")
        end_ip = get_nested(resource, "values", "end_ip_address", default="")
        if start_ip == "0.0.0.0" and end_ip in {"0.0.0.0", "255.255.255.255"}:
            wide_open_rules.append(resource.get("address", "unknown"))
    if _disabled(public_access) and delegated_subnet and private_dns and not wide_open_rules:
        return True, _with_microsoft_learn_evidence(
            "public network access is disabled, VNET integration is configured, and no wide-open firewall rules exist.",
            "network_restrictions",
        )
    if wide_open_rules:
        return False, f"wide-open firewall rules found: {', '.join(wide_open_rules)}."
    return False, "expected public_network_access_enabled=false with delegated_subnet_id and private_dns_zone_id."


def _check_centralized_logs(server: dict, related: list[dict]) -> tuple[bool, str]:
    for setting in _matching_diagnostic_settings(server, related):
        workspace = get_nested(setting, "values", "log_analytics_workspace_id")
        eventhub = get_nested(setting, "values", "eventhub_authorization_rule_id")
        storage = get_nested(setting, "values", "storage_account_id")
        if (workspace or eventhub or storage) and _diag_exports_postgres_logs(setting):
            destination = workspace or eventhub or storage
            return True, _with_microsoft_learn_evidence(
                f"diagnostic setting exports PostgreSQL logs to {destination}.",
                "centralized_logs",
            )
    return False, "no diagnostic setting exports PostgreSQL logs to a centralized destination."


def _check_log_timezone(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(_param_value(related, "log_timezone", "")).upper()
    if value == "UTC":
        return True, _with_microsoft_learn_evidence(
            "log_timezone=UTC.",
            "log_timezone",
        )
    return False, f"log_timezone={value or 'not configured'}; expected UTC."


def _check_timestamp_granularity(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    if "%m" in prefix:
        return True, _with_microsoft_learn_evidence(
            "log_line_prefix uses %m, which records timestamps with milliseconds.",
            "timestamp_granularity",
        )
    return False, "log_line_prefix does not use %m for one-second-or-better timestamp granularity."


def _check_approved_ca_tls(server: dict, related: list[dict]) -> tuple[bool, str]:
    if _tls_is_modern(server, related):
        version = _tls_min_version(server, related)
        return True, _with_microsoft_learn_evidence(
            f"minimum TLS version is {version}; Azure manages server certificates for encrypted sessions.",
            "approved_ca_tls",
        )
    return False, "minimum TLS version is not configured to TLS 1.2 or higher."


def _check_audit_event_location(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    required = {"%m", "%u", "%d", "%s"}
    missing = {token for token in required if token not in prefix}
    if not missing:
        return True, _with_microsoft_learn_evidence(
            f"log_line_prefix={prefix} includes timestamp, user, database, and process-start fields.",
            "audit_event_location",
        )
    return False, f"log_line_prefix is missing location fields: {', '.join(sorted(missing))}."


def _check_audit_event_source(_server: dict, related: list[dict]) -> tuple[bool, str]:
    prefix = _log_line_prefix(related)
    if not _config_is_on(related, "log_hostname"):
        return False, "log_hostname is not enabled."
    if "%h" not in prefix and "%r" not in prefix:
        return False, "log_line_prefix does not include %h or %r source fields."
    return True, _with_microsoft_learn_evidence(
        "log_hostname=on and log_line_prefix captures the connection source.",
        "audit_event_source",
    )


def _check_audit_event_outcome(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(_param_value(related, "log_error_verbosity", "")).lower()
    if value == "verbose":
        return True, _with_microsoft_learn_evidence(
            "log_error_verbosity=verbose.",
            "audit_event_outcome",
        )
    return False, f"log_error_verbosity={value or 'not configured'}; expected verbose."


def _check_client_error_messages(_server: dict, related: list[dict]) -> tuple[bool, str]:
    value = str(_param_value(related, "client_min_messages", "")).lower()
    if value == "error":
        return True, _with_microsoft_learn_evidence(
            "client_min_messages=error.",
            "client_error_messages",
        )
    return False, f"client_min_messages={value or 'not configured'}; expected error."


def _check_session_timeout(_server: dict, related: list[dict]) -> tuple[bool, str]:
    idle_session = _param_value(related, "idle_session_timeout")
    idle_in_transaction = _param_value(related, "idle_in_transaction_session_timeout")
    statement = _param_value(related, "statement_timeout")
    configured = []
    if _positive_duration(idle_session):
        configured.append(f"idle_session_timeout={idle_session}")
    if _positive_duration(idle_in_transaction):
        configured.append(f"idle_in_transaction_session_timeout={idle_in_transaction}")
    if _positive_duration(statement):
        configured.append(f"statement_timeout={statement}")
    if configured:
        return True, _with_microsoft_learn_evidence(
            "; ".join(configured) + "; a finite session/statement timeout is configured.",
            "session_timeout",
        )
    return False, (
        "idle_session_timeout, idle_in_transaction_session_timeout, or "
        "statement_timeout must be a positive duration."
    )


CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str]]] = {
    "supported_version": _check_supported_version,
    "managed_security_updates": _check_managed_security_updates,
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
    module_name="postgres_flexible",
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
class PostgresFlexibleStigModule(BaseStigModule):
    """Azure PostgreSQL Flexible Server STIG compliance module."""

    name = "postgres_flexible"
    description = "Crunchy Data Postgres 16 STIG — azurerm_postgresql_flexible_server"
    resource_type = "azurerm_postgresql_flexible_server"
    related_resource_types = {
        "azurerm_monitor_diagnostic_setting",
        "azurerm_postgresql_flexible_server_active_directory_administrator",
        "azurerm_postgresql_flexible_server_configuration",
        "azurerm_postgresql_flexible_server_firewall_rule",
    }
    report_title = "Azure PostgreSQL Flexible Server STIG Report"

    stig_benchmark_id = "CD_Postgres_16_STIG"
    stig_benchmark_title = "Crunchy Data Postgres 16 Security Technical Implementation Guide"
    stig_version = "1"
    stig_release_info = "Release: 2 Benchmark Date: 01 Apr 2026"

    def controls(self) -> list[StigControl]:
        """Return the Crunchy Data Postgres 16 STIG control catalogue."""
        return STIG_CONTROLS

    def find_resources(
        self,
        all_resources: list[dict],
    ) -> list[tuple[dict, list[dict]]]:
        """Find PostgreSQL servers and matching configuration/diagnostic resources."""
        primaries = filter_by_type(all_resources, self.resource_type)
        related = [r for r in all_resources if r.get("type") in self.related_resource_types]

        result: list[tuple[dict, list[dict]]] = []
        for primary in primaries:
            primary_id = get_nested(primary, "values", "id", default="")
            primary_name = get_nested(primary, "values", "name", default="")
            matched = []
            for resource in related:
                server_id = get_nested(resource, "values", "server_id", default="")
                server_name = get_nested(resource, "values", "server_name", default="")
                target_id = get_nested(resource, "values", "target_resource_id", default="")
                if (
                    (primary_id and server_id == primary_id)
                    or (primary_id and target_id == primary_id)
                    or (primary_name and server_name == primary_name)
                ):
                    matched.append(resource)
            result.append((primary, matched))
        return result
