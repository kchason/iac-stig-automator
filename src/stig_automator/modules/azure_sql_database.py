"""Azure SQL Database checks for the Microsoft Azure SQL Database STIG."""

from __future__ import annotations

from typing import Callable

from ..models import Severity, StigControl
from ..plan_parser import filter_by_type
from ..registry import register
from ..util import get_nested
from ._aws import load_json_file
from ._base import BaseStigModule
from ._mapping import ControlMapping, load_control_mappings, make_platform_check

CONTROLS_FILE = "stigs/azure_sql_database_controls.json"
CONTROL_MAPPINGS_FILE = "mappings/azure_sql_database_controls.json"
EVIDENCE_FILE = "mappings/azure_sql_database_evidence.json"

CONTROL_DATA: list[dict[str, object]] = list(load_json_file(CONTROLS_FILE))
CONTROL_MAPPING_DATA: dict[str, object] = dict(load_json_file(CONTROL_MAPPINGS_FILE))
EVIDENCE: dict[str, dict[str, object]] = dict(load_json_file(EVIDENCE_FILE))


def _truthy(value: object) -> bool:
    return value is True or str(value).strip().lower() in {"1", "on", "true", "enabled", "yes"}


def _disabled(value: object) -> bool:
    return value is False or str(value).strip().lower() in {"0", "off", "false", "disabled", "no"}


def _with_evidence(detail: str, evidence_key: str) -> str:
    evidence = EVIDENCE[evidence_key]
    quote = str(evidence["quote"])
    url = str(evidence["url"])
    terraform_urls = [str(item) for item in evidence.get("terraform_urls", [])]
    properties = [str(prop) for prop in evidence.get("terraform_properties", [])]
    terraform_properties = ""
    if properties:
        terraform_properties = f" Terraform properties addressed: {'; '.join(properties)}."
    terraform_docs = ""
    if terraform_urls:
        terraform_docs = f" Terraform provider docs: {', '.join(terraform_urls)}"
    return f'{detail} Microsoft Learn evidence: "{quote}" ({url}){terraform_properties}{terraform_docs}'


def _remediation_comment(evidence_key: str) -> str:
    evidence = EVIDENCE[evidence_key]
    terraform_urls = [str(item) for item in evidence.get("terraform_urls", [])]
    properties = [str(prop) for prop in evidence.get("terraform_properties", [])]
    if not terraform_urls or not properties:
        return ""
    return (
        "Terraform remediation: configure "
        f"{'; '.join(properties)}. Provider docs: {', '.join(terraform_urls)}"
    )


def _platform_detail(mapping: ControlMapping, vuln_id: str, title: str) -> str:
    detail = mapping.automatic_platform_text.format(vuln_id=vuln_id, title=title)
    if mapping.evidence_key:
        evidence = EVIDENCE[mapping.evidence_key]
        detail = (
            f'{detail} Microsoft Learn evidence: "{evidence["quote"]}" ({evidence["url"]})'
        )
    return detail


def _entra_admin_configured(server: dict, related: list[dict]) -> bool:
    admin = get_nested(server, "values", "azuread_administrator") or {}
    if get_nested(admin, "login_username") or get_nested(admin, "object_id"):
        return True
    for resource in related:
        if resource.get("type") == "azurerm_mssql_server_azuread_administrator":
            return True
    return False


def _extended_auditing_policy(related: list[dict]) -> dict | None:
    for resource in related:
        if resource.get("type") == "azurerm_mssql_server_extended_auditing_policy":
            return resource
    return None


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


def _tls_is_modern(value: object) -> bool:
    normalized = str(value or "").lower().replace("_", "").replace(".", "")
    return "tls12" in normalized or "tls13" in normalized or normalized in {"12", "13"}


def _check_entra_only_auth(server: dict, related: list[dict]) -> tuple[bool, str]:
    only_entra = _truthy(get_nested(server, "values", "azuread_authentication_only"))
    if only_entra and _entra_admin_configured(server, related):
        return True, _with_evidence(
            "azuread_authentication_only=true and an Azure AD administrator is configured.",
            "entra_only_auth",
        )
    if only_entra:
        return False, "azuread_authentication_only=true but no Azure AD administrator is configured."
    return False, "azuread_authentication_only is not enabled for this SQL server."


def _check_minimum_tls(server: dict, _related: list[dict]) -> tuple[bool, str]:
    version = get_nested(server, "values", "minimum_tls_version", default="")
    if _tls_is_modern(version):
        return True, _with_evidence(
            f"minimum_tls_version={version}.",
            "minimum_tls",
        )
    return False, f"minimum_tls_version={version or 'not configured'}; expected TLS 1.2 or newer."


def _check_public_network_access(server: dict, _related: list[dict]) -> tuple[bool, str]:
    value = get_nested(server, "values", "public_network_access_enabled")
    if _disabled(value):
        return True, _with_evidence(
            "public_network_access_enabled=false.",
            "public_network_access",
        )
    return False, f"public_network_access_enabled={value}; expected false."


def _check_azure_services_firewall(_server: dict, related: list[dict]) -> tuple[bool, str]:
    violations = []
    for resource in related:
        if resource.get("type") != "azurerm_mssql_firewall_rule":
            continue
        name = str(get_nested(resource, "values", "name", default=""))
        start_ip = str(get_nested(resource, "values", "start_ip_address", default=""))
        end_ip = str(get_nested(resource, "values", "end_ip_address", default=""))
        if name == "AllowAllWindowsAzureIps" or (start_ip == "0.0.0.0" and end_ip == "0.0.0.0"):
            violations.append(resource.get("address", name))
    if not violations:
        return True, _with_evidence(
            "No AllowAllWindowsAzureIps or 0.0.0.0 Azure services firewall exception is configured.",
            "azure_services_firewall",
        )
    return False, f"Azure services firewall exceptions found: {', '.join(violations)}."


def _check_tde_enabled(server: dict, related: list[dict]) -> tuple[bool, str]:
    databases = [resource for resource in related if resource.get("type") == "azurerm_mssql_database"]
    if databases:
        disabled = []
        for database in databases:
            value = get_nested(database, "values", "transparent_data_encryption_enabled", default=True)
            if _disabled(value):
                disabled.append(database.get("address", "unknown"))
        if disabled:
            return False, (
                "transparent_data_encryption_enabled=false for databases: "
                f"{', '.join(disabled)}."
            )
        return True, _with_evidence(
            "All related azurerm_mssql_database resources keep transparent data encryption enabled.",
            "tde_enabled",
        )

    for resource in related:
        if resource.get("type") == "azurerm_mssql_server_transparent_data_encryption":
            key_id = get_nested(resource, "values", "key_vault_key_id")
            if key_id:
                return True, _with_evidence(
                    f"Server transparent data encryption uses key_vault_key_id={key_id}.",
                    "tde_enabled",
                )

    return True, _with_evidence(
        "No databases disable TDE in plan data; Azure SQL Database enables transparent data encryption by default.",
        "tde_enabled",
    )


def _check_extended_auditing(_server: dict, related: list[dict]) -> tuple[bool, str]:
    policy = _extended_auditing_policy(related)
    if policy is None:
        return False, "azurerm_mssql_server_extended_auditing_policy is not configured."

    storage_endpoint = get_nested(policy, "values", "storage_endpoint")
    log_monitoring = get_nested(policy, "values", "log_monitoring_enabled")
    enabled = get_nested(policy, "values", "enabled", default=True)
    if _truthy(enabled) and (storage_endpoint or _truthy(log_monitoring)):
        destination = storage_endpoint or "Log Analytics via log_monitoring_enabled"
        return True, _with_evidence(
            f"SQL auditing is configured with destination {destination}.",
            "extended_auditing",
        )
    return False, "Extended auditing is not configured with a storage endpoint or Log Analytics export."


def _check_audit_offload(server: dict, related: list[dict]) -> tuple[bool, str]:
    for setting in _matching_diagnostic_settings(server, related):
        workspace = get_nested(setting, "values", "log_analytics_workspace_id")
        storage = get_nested(setting, "values", "storage_account_id")
        if workspace or storage:
            destination = workspace or storage
            return True, _with_evidence(
                f"Diagnostic settings export SQL audit telemetry to {destination}.",
                "audit_offload",
            )

    policy = _extended_auditing_policy(related)
    if policy is not None:
        storage_endpoint = get_nested(policy, "values", "storage_endpoint")
        log_monitoring = get_nested(policy, "values", "log_monitoring_enabled")
        if storage_endpoint or _truthy(log_monitoring):
            destination = storage_endpoint or "Log Analytics via log_monitoring_enabled"
            return True, _with_evidence(
                f"Extended auditing offloads records to {destination}.",
                "audit_offload",
            )

    return False, "No diagnostic setting or extended auditing destination is configured for audit offload."


CHECKS: dict[str, Callable[[dict, list[dict]], tuple[bool, str]]] = {
    "entra_only_auth": _check_entra_only_auth,
    "minimum_tls": _check_minimum_tls,
    "public_network_access": _check_public_network_access,
    "azure_services_firewall": _check_azure_services_firewall,
    "tde_enabled": _check_tde_enabled,
    "extended_auditing": _check_extended_auditing,
    "audit_offload": _check_audit_offload,
}
CONTROL_MAPPINGS = load_control_mappings(
    CONTROL_MAPPING_DATA,
    module_name="azure_sql_database",
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
class AzureSqlDatabaseStigModule(BaseStigModule):
    """Azure SQL Database STIG compliance module."""

    name = "azure_sql_database"
    description = "Microsoft Azure SQL Database STIG — azurerm_mssql_server"
    resource_type = "azurerm_mssql_server"
    related_resource_types = {
        "azurerm_mssql_database",
        "azurerm_mssql_firewall_rule",
        "azurerm_mssql_server_azuread_administrator",
        "azurerm_mssql_server_extended_auditing_policy",
        "azurerm_mssql_server_transparent_data_encryption",
        "azurerm_mssql_virtual_network_rule",
        "azurerm_monitor_diagnostic_setting",
    }
    report_title = "Azure SQL Database STIG Report"

    stig_benchmark_id = "MS_Azure_SQL_DB_STIG"
    stig_benchmark_title = "Microsoft Azure SQL Database Security Technical Implementation Guide"
    stig_version = "2"
    stig_release_info = "Release: 2 Benchmark Date: 24 Oct 2024"

    def controls(self) -> list[StigControl]:
        """Return the Azure SQL Database STIG control catalogue."""
        return STIG_CONTROLS

    def find_resources(self, all_resources: list[dict]) -> list[tuple[dict, list[dict]]]:
        """Find SQL servers and matching firewall, auditing, and database resources."""
        primaries = filter_by_type(all_resources, self.resource_type)
        related = [resource for resource in all_resources if resource.get("type") in self.related_resource_types]

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
