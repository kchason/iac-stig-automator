"""MySQL Flexible Server STIG module — azurerm_mysql_flexible_server checks."""

from __future__ import annotations

import json
from importlib import resources
from typing import Callable

from ..models import Severity, StigControl
from ..registry import register
from ..util import first_nested, get_nested
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

MYSQL_CONTROLS_FILE = "stigs/mysql_flexible_controls.json"
MYSQL_CONTROL_MAPPINGS_FILE = "mappings/mysql_flexible_controls.json"
MYSQL_EVIDENCE_FILE = "mappings/mysql_flexible_evidence.json"


def _load_json_file(filename: str) -> object:
    with resources.files(__package__).joinpath(filename).open(encoding="utf-8") as f:
        return json.load(f)


MYSQL_CONTROL_DATA: list[dict[str, object]] = list(_load_json_file(MYSQL_CONTROLS_FILE))
MYSQL_CONTROL_MAPPING_DATA: dict[str, object] = dict(_load_json_file(MYSQL_CONTROL_MAPPINGS_FILE))
MYSQL_EVIDENCE: dict[str, dict[str, object]] = dict(_load_json_file(MYSQL_EVIDENCE_FILE))


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------

def _with_microsoft_learn_evidence(detail: str, evidence_key: str) -> str:
    evidence = MYSQL_EVIDENCE[evidence_key]
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
    evidence = MYSQL_EVIDENCE[evidence_key]
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
    evidence = MYSQL_EVIDENCE[mapping.evidence_key]
    quote = str(evidence["quote"])
    url = str(evidence["url"])
    return f'Microsoft Learn evidence: "{quote}" ({url}) Inherited CSP/baseline controls: {detail}'


def _get_server_param(related: list[dict], param_name: str) -> dict | None:
    """Find an azurerm_mysql_flexible_server_configuration resource by name."""
    for r in related:
        if r.get("type") == "azurerm_mysql_flexible_server_configuration":
            if get_nested(r, "values", "name") == param_name:
                return r
    return None


def _missing_azure_mysql_audit_events(value: object) -> list[str]:
    """Return Azure-native audit event classes missing from audit_log_events."""
    tokens = _audit_event_tokens(value)
    missing = []
    if not ({"CONNECTION", "CONNECTION_V2"} & tokens):
        missing.append("CONNECTION or CONNECTION_V2")
    if not ({"DCL", "GENERAL"} & tokens):
        missing.append("DCL or GENERAL")
    if not ({"DDL", "GENERAL"} & tokens):
        missing.append("DDL or GENERAL")
    return missing


# ---------------------------------------------------------------------------
# Check functions — each takes (server, related) -> (bool, str)
# ---------------------------------------------------------------------------

def _truthy_mysql(value: object) -> bool:
    return value is True or str(value).strip().upper() in {"1", "ON", "TRUE", "ENABLED", "YES"}


def _audit_log_enabled(server: dict, related: list[dict]) -> bool:
    val = get_nested(server, "values", "audit_log_enabled")
    if val is not None:
        return _truthy_mysql(val)
    cfg = _get_server_param(related, "audit_log_enabled")
    cfg_val = get_nested(cfg, "values", "value", default="") if cfg else ""
    return _truthy_mysql(cfg_val)


def _audit_event_tokens(value: object) -> set[str]:
    tokens = {
        token.strip().strip("'\"").upper()
        for token in str(value or "").replace(";", ",").split(",")
        if token.strip()
    }
    if "CONNECTION_V2" in tokens:
        tokens.add("CONNECTION")
    if "GENERAL" in tokens:
        tokens.update({"DCL", "DDL", "DML"})
    if "TABLE_ACCESS" in tokens or {"DML_SELECT", "DML_NONSELECT"} & tokens:
        tokens.add("DML")
    return tokens


def _check_tls_enforced(server: dict, related: list[dict]) -> tuple[bool, str]:
    val = get_nested(server, "values", "require_secure_transport")
    if val is not None:
        val_str = str(val).upper()
        if val_str in ("ON", "TRUE"):
            return True, _with_microsoft_learn_evidence(
                "require_secure_transport=ON — All client connections must use TLS encryption, "
                "preventing unencrypted data from traversing the network.",
                "tls_enforced",
            )
        return False, f"require_secure_transport={val} - unencrypted client connections are permitted"
    cfg = _get_server_param(related, "require_secure_transport")
    if cfg:
        cfg_val = get_nested(cfg, "values", "value", default="")
        if cfg_val.upper() in ("ON", "TRUE"):
            return True, _with_microsoft_learn_evidence(
                "require_secure_transport=ON (set via azurerm_mysql_flexible_server_configuration) — "
                "All client connections must use TLS encryption, preventing unencrypted data from traversing the network.",
                "tls_enforced",
            )
        return False, f"require_secure_transport={cfg_val} via configuration resource - unencrypted connections are permitted"
    return False, "require_secure_transport not configured - defaults may allow unencrypted connections"


def _check_tls_version(server: dict, related: list[dict]) -> tuple[bool, str]:
    val = get_nested(server, "values", "tls_version")
    if not val:
        cfg = _get_server_param(related, "tls_version")
        val = get_nested(cfg, "values", "value") if cfg else None
    if val:
        val_upper = val.upper().replace(" ", "")
        if "TLSV1.2" in val_upper or "TLSV1.3" in val_upper:
            has_old = "TLSV1.0" in val_upper or "TLSV1.1" in val_upper
            if has_old:
                return False, f"tls_version={val} - TLS 1.0 or 1.1 is still permitted alongside newer versions"
            return True, _with_microsoft_learn_evidence(
                f"tls_version={val} — Only TLS 1.2 or higher is permitted for client connections, "
                "ensuring strong encryption and protection against known TLS downgrade attacks.",
                "tls_version",
            )
        return False, f"tls_version={val} - does not enforce TLS 1.2+"
    return False, "tls_version not explicitly configured - verify the server default enforces TLS 1.2+"


def _check_max_user_connections(server: dict, related: list[dict]) -> tuple[bool, str]:
    value = get_nested(server, "values", "max_user_connections")
    cfg = _get_server_param(related, "max_user_connections")
    if value is None:
        value = get_nested(cfg, "values", "value") if cfg else None
    if value is None:
        return False, "max_user_connections is not explicitly configured."
    try:
        limit = int(str(value))
    except ValueError:
        return False, f"max_user_connections={value}; unable to parse numeric limit."
    if limit > 0:
        return True, _with_microsoft_learn_evidence(
            f"max_user_connections={limit}; a finite per-user concurrent session limit is configured.",
            "max_user_connections",
        )
    return False, f"max_user_connections={limit}; expected a positive finite per-user session limit."


def _check_audit_log_enabled(server: dict, related: list[dict]) -> tuple[bool, str]:
    val = get_nested(server, "values", "audit_log_enabled")
    if val is not None:
        if _truthy_mysql(val):
            return True, _with_microsoft_learn_evidence(
                "audit_log_enabled=ON — MySQL audit logging is active, recording database access events "
                "for security monitoring, forensic analysis, and compliance auditing.",
                "audit_log_enabled",
            )
        return False, f"audit_log_enabled={val} - audit logging is disabled"
    cfg = _get_server_param(related, "audit_log_enabled")
    if cfg:
        cfg_val = get_nested(cfg, "values", "value", default="")
        if _truthy_mysql(cfg_val):
            return True, _with_microsoft_learn_evidence(
                "audit_log_enabled=ON (set via azurerm_mysql_flexible_server_configuration) — "
                "MySQL audit logging is active, recording database access events for security monitoring and compliance.",
                "audit_log_enabled",
            )
        return False, f"audit_log_enabled={cfg_val} via configuration resource - audit logging is disabled"
    return False, "audit_log_enabled not configured - database access events are not being recorded"


def _check_audit_log_events(server: dict, related: list[dict]) -> tuple[bool, str]:
    if not _audit_log_enabled(server, related):
        return False, "audit_log_enabled is not enabled; audit events cannot satisfy the STIG audit requirements."
    val = get_nested(server, "values", "audit_log_events")
    if not val:
        cfg = _get_server_param(related, "audit_log_events")
        val = get_nested(cfg, "values", "value") if cfg else None
    if val:
        required = {"CONNECTION", "DCL", "DDL", "DML"}
        found = _audit_event_tokens(val)
        missing = required - found
        if not missing:
            return True, _with_microsoft_learn_evidence(
                f"audit_log_events={val} (normalized: {', '.join(sorted(found))}) — Azure MySQL audit "
                "events include connection tracking, DCL (permission changes), DDL (schema changes), "
                "and DML (object access), capturing critical categories needed for STIG audit rules.",
                "audit_log_events",
            )
        return False, (
            f"audit_log_events={val} (normalized: {', '.join(sorted(found))}) - "
            f"missing recommended event types: {', '.join(sorted(missing))}"
        )
    return False, "audit_log_events not configured - no audit event categories are being captured"


def _check_public_network_access(server: dict, related: list[dict]) -> tuple[bool, str]:
    val = get_nested(server, "values", "public_network_access_enabled")
    if val is not None:
        if str(val).lower() in ("false", "disabled"):
            return True, _with_microsoft_learn_evidence(
                "public_network_access_enabled=false — The server is not reachable from the public internet. "
                "All connections must traverse a private endpoint or VNET integration, limiting network exposure.",
                "public_network_access",
            )
        return False, "public_network_access_enabled=true - the server is reachable from the public internet"
    val = get_nested(server, "values", "public_network_access")
    if val is not None:
        if str(val).lower() in ("disabled", "false"):
            return True, _with_microsoft_learn_evidence(
                "public_network_access=Disabled — The server is not reachable from the public internet, "
                "limiting network exposure to private endpoints or VNET integration.",
                "public_network_access",
            )
        return False, f"public_network_access={val} - the server is reachable from the public internet"
    return False, "public_network_access_enabled not set - verify the server is not exposed to public networks"


def _check_backup_retention(server: dict, related: list[dict]) -> tuple[bool, str]:
    val = get_nested(server, "values", "backup_retention_days")
    if val is not None:
        val = int(val)
        if val >= 7:
            return True, _with_microsoft_learn_evidence(
                f"backup_retention_days={val} — Backups are retained for {val} days, meeting the minimum "
                "retention requirement for disaster recovery and point-in-time restore capabilities.",
                "backup_retention",
            )
        return False, f"backup_retention_days={val} - below the recommended minimum of 7 days"
    return False, "backup_retention_days not set - relying on the platform default; verify it meets retention requirements"


def _check_geo_redundant_backup(server: dict, related: list[dict]) -> tuple[bool, str]:
    val = get_nested(server, "values", "geo_redundant_backup_enabled")
    if val is not None:
        if str(val).lower() == "true" or val is True:
            return True, _with_microsoft_learn_evidence(
                "geo_redundant_backup_enabled=true — Backups are replicated to a paired Azure region, "
                "protecting against regional outages and satisfying geographic redundancy requirements for data recovery.",
                "geo_redundant_backup",
            )
        return False, "geo_redundant_backup_enabled=false - backups are stored in a single region only"
    return False, "geo_redundant_backup_enabled not set - backups may not be geographically redundant"


def _check_high_availability(server: dict, related: list[dict]) -> tuple[bool, str]:
    ha = first_nested(server, "values", "high_availability")
    if ha:
        mode = get_nested(ha, "mode", default="")
        if mode.lower() in ("zoneredundant", "zone_redundant"):
            return True, _with_microsoft_learn_evidence(
                f"high_availability.mode={mode} — The server is deployed across multiple availability zones, "
                "providing automatic failover and ensuring database availability during zone-level failures.",
                "high_availability_zone",
            )
        if mode.lower() == "samezone":
            return True, _with_microsoft_learn_evidence(
                f"high_availability.mode={mode} — High availability is configured within the same zone. "
                "This provides failover capability, though cross-zone redundancy would offer stronger protection.",
                "high_availability_same_zone",
            )
        return False, f"high_availability.mode={mode} - unrecognized HA mode"
    return False, "high_availability block not configured - the server has no automatic failover capability"


def _check_cmk_encryption(server: dict, related: list[dict]) -> tuple[bool, str]:
    cmk = first_nested(server, "values", "customer_managed_key")
    if cmk:
        key_vault_key_id = get_nested(cmk, "key_vault_key_id")
        if key_vault_key_id:
            return True, _with_microsoft_learn_evidence(
                f"customer_managed_key.key_vault_key_id={key_vault_key_id} — Data at rest is encrypted "
                "using a customer-managed key stored in Azure Key Vault, providing full control over the "
                "encryption key lifecycle and meeting CMK encryption requirements.",
                "cmk_encryption",
            )
        return False, "customer_managed_key block present but key_vault_key_id not set"
    return False, "customer_managed_key not configured - data at rest uses platform-managed keys only"


def _check_identity(server: dict, related: list[dict]) -> tuple[bool, str]:
    identity = first_nested(server, "values", "identity")
    if identity:
        id_type = get_nested(identity, "type", default="")
        if id_type in ("SystemAssigned", "UserAssigned", "SystemAssigned,UserAssigned"):
            return True, _with_microsoft_learn_evidence(
                f"identity.type={id_type} — The server uses a Managed Identity for authenticating to "
                "Azure services (e.g., Key Vault for CMK encryption), eliminating the need for stored credentials.",
                "identity",
            )
        return False, f"identity.type={id_type} - unrecognized identity type"
    return False, "identity block not configured - the server cannot use Managed Identity for service-to-service authentication"


def _check_private_dns_zone(server: dict, related: list[dict]) -> tuple[bool, str]:
    zone_id = get_nested(server, "values", "private_dns_zone_id")
    if zone_id:
        return True, _with_microsoft_learn_evidence(
            f"private_dns_zone_id={zone_id} — The server is integrated with a private DNS zone, ensuring "
            "name resolution is confined to the private network and not exposed via public DNS.",
            "private_dns_zone",
        )
    return False, "private_dns_zone_id not set - the server may be resolvable via public DNS"


def _check_delegated_subnet(server: dict, related: list[dict]) -> tuple[bool, str]:
    subnet_id = get_nested(server, "values", "delegated_subnet_id")
    if subnet_id:
        return True, _with_microsoft_learn_evidence(
            f"delegated_subnet_id={subnet_id} — The server is deployed into a delegated subnet within "
            "the virtual network, isolating database traffic from the public internet and enabling NSG-level controls.",
            "delegated_subnet",
        )
    return False, "delegated_subnet_id not set - the server is not deployed into a VNET-delegated subnet"


def _check_storage_auto_grow(server: dict, related: list[dict]) -> tuple[bool, str]:
    storage = first_nested(server, "values", "storage")
    if storage:
        auto_grow = get_nested(storage, "auto_grow_enabled", default=None)
        if auto_grow is True or str(auto_grow).lower() == "true":
            return True, _with_microsoft_learn_evidence(
                "storage.auto_grow_enabled=true — Storage will automatically expand when nearing capacity, "
                "preventing service disruptions caused by disk-full conditions.",
                "storage_auto_grow",
            )
        if auto_grow is not None:
            return False, f"storage.auto_grow_enabled={auto_grow} - storage will not expand automatically"
    auto_grow = get_nested(server, "values", "storage_auto_grow_enabled")
    if auto_grow is True or str(auto_grow).lower() in ("true", "enabled"):
        return True, _with_microsoft_learn_evidence(
            "storage_auto_grow_enabled=true — Storage will automatically expand when nearing capacity, "
            "preventing service disruptions caused by disk-full conditions.",
            "storage_auto_grow",
        )
    return False, "storage auto_grow not enabled - the server may run out of storage under load"


def _check_slow_query_log(server: dict, related: list[dict]) -> tuple[bool, str]:
    val = get_nested(server, "values", "slow_query_log")
    if val is not None and str(val).upper() in ("ON", "TRUE"):
        return True, _with_microsoft_learn_evidence(
            "slow_query_log=ON — Slow query logging is enabled, aiding in identifying long-running queries "
            "that may indicate performance issues or potential abuse of database resources.",
            "slow_query_log",
        )
    cfg = _get_server_param(related, "slow_query_log")
    if cfg:
        cfg_val = get_nested(cfg, "values", "value", default="")
        if cfg_val.upper() in ("ON", "TRUE"):
            return True, _with_microsoft_learn_evidence(
                "slow_query_log=ON (set via azurerm_mysql_flexible_server_configuration) — Slow query logging "
                "is enabled for identifying long-running queries and potential resource abuse.",
                "slow_query_log",
            )
        return False, f"slow_query_log={cfg_val} via configuration resource - slow query logging is disabled"
    return False, "slow_query_log not configured - long-running queries are not being tracked"


def _check_maintenance_window(server: dict, related: list[dict]) -> tuple[bool, str]:
    mw = first_nested(server, "values", "maintenance_window")
    if mw:
        day = get_nested(mw, "day_of_week")
        start_hour = get_nested(mw, "start_hour")
        if day is not None and start_hour is not None:
            return True, _with_microsoft_learn_evidence(
                f"maintenance_window configured (day_of_week={day}, start_hour={start_hour}) — "
                "A custom maintenance window is set, ensuring platform-initiated patching occurs during "
                "a predictable, low-impact period rather than at an arbitrary time.",
                "maintenance_window",
            )
    return False, "maintenance_window not configured - platform patching will occur at an Azure-chosen time"


def _check_sku_not_burstable(server: dict, related: list[dict]) -> tuple[bool, str]:
    sku = get_nested(server, "values", "sku_name", default="")
    if sku.startswith("B_"):
        return False, (
            f"sku_name={sku} - Burstable SKUs are intended for dev/test workloads and may not provide "
            "consistent performance or SLA guarantees required for production databases"
        )
    if sku:
        tier = "General Purpose" if sku.startswith("GP_") else "Memory Optimized" if sku.startswith("MO_") else sku
        return True, _with_microsoft_learn_evidence(
            f"sku_name={sku} ({tier}) — The server uses a production-grade SKU that provides consistent "
            "compute performance and is backed by a production SLA.",
            "sku_not_burstable",
        )
    return False, "sku_name not set - unable to determine if the SKU meets production requirements"


def _check_version(server: dict, related: list[dict]) -> tuple[bool, str]:
    version = get_nested(server, "values", "version")
    if version:
        try:
            major = int(str(version).split(".")[0])
            if major >= 8:
                return True, _with_microsoft_learn_evidence(
                    f"version={version} — The server runs MySQL {version}, which is a currently supported "
                    "major version receiving security patches and bug fixes.",
                    "version",
                )
            return False, f"version={version} - this version may be approaching or past end-of-life"
        except (ValueError, IndexError):
            return False, f"version={version} - unable to parse version number"
    return False, "version not set - verify the server is running a supported MySQL version"


CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str] | tuple[bool, str, bool]]] = {
    "tls_enforced": _check_tls_enforced,
    "tls_version": _check_tls_version,
    "max_user_connections": _check_max_user_connections,
    "audit_log_enabled": _check_audit_log_enabled,
    "audit_log_events": _check_audit_log_events,
    "public_network_access": _check_public_network_access,
    "delegated_subnet": _check_delegated_subnet,
    "private_dns_zone": _check_private_dns_zone,
    "backup_retention": _check_backup_retention,
    "geo_redundant_backup": _check_geo_redundant_backup,
    "high_availability": _check_high_availability,
    "cmk_encryption": _check_cmk_encryption,
    "identity": _check_identity,
    "slow_query_log": _check_slow_query_log,
    "storage_auto_grow": _check_storage_auto_grow,
    "sku_not_burstable": _check_sku_not_burstable,
    "version": _check_version,
    "maintenance_window": _check_maintenance_window,
}
MYSQL_CONTROL_MAPPINGS = load_control_mappings(
    MYSQL_CONTROL_MAPPING_DATA,
    module_name="mysql_flexible",
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
class MysqlFlexibleStigModule(BaseStigModule):
    """Azure MySQL Flexible Server STIG compliance module."""

    name = "mysql_flexible"
    description = "Oracle MySQL 8.0 STIG — azurerm_mysql_flexible_server"
    resource_type = "azurerm_mysql_flexible_server"
    related_resource_types = {
        "azurerm_mysql_flexible_server_configuration",
        "azurerm_mysql_flexible_server_firewall_rule",
        "azurerm_mysql_flexible_server_active_directory_administrator",
    }
    report_title = "MySQL Flexible Server STIG Report"

    stig_benchmark_id = "Oracle_MySQL_8.0_STIG"
    stig_benchmark_title = "Oracle MySQL 8.0 Security Technical Implementation Guide"
    stig_version = "2"
    stig_release_info = "Release: 2 Benchmark Date: 24 Oct 2024"

    def controls(self) -> list[StigControl]:
        """Return the MySQL 8.0 STIG control catalogue."""
        return STIG_CONTROLS
