"""Shared helpers for AWS Terraform-backed STIG modules."""

from __future__ import annotations

import json
from importlib import resources

from ..util import get_nested


def load_json_file(filename: str) -> object:
    """Load a JSON data file bundled with the modules package."""
    with resources.files(__package__).joinpath(filename).open(encoding="utf-8") as f:
        return json.load(f)


def truthy(value: object) -> bool:
    """Return true for common Terraform/AWS truthy representations."""
    return value is True or str(value).strip().lower() in {"1", "on", "true", "enabled", "yes"}


def disabled(value: object) -> bool:
    """Return true for common Terraform/AWS disabled representations."""
    return value is False or str(value).strip().lower() in {"0", "off", "false", "disabled", "no"}


def csv_tokens(value: object) -> set[str]:
    """Normalize comma/semicolon-separated configuration values."""
    return {
        token.strip().strip("'\"").lower()
        for token in str(value or "").replace(";", ",").split(",")
        if token.strip()
    }


def with_aws_evidence(detail: str, evidence_key: str, evidence: dict[str, dict[str, object]]) -> str:
    """Append AWS documentation and Terraform provider references to a check detail."""
    item = evidence[evidence_key]
    quote = str(item["quote"])
    url = str(item["url"])
    terraform_urls = [str(url) for url in item.get("terraform_urls", [])]
    rdbms_urls = [str(url) for url in item.get("rdbms_urls", [])]
    properties = [str(prop) for prop in item.get("terraform_properties", [])]
    terraform_properties = ""
    if properties:
        terraform_properties = f" Terraform properties addressed: {'; '.join(properties)}."
    terraform_docs = ""
    if terraform_urls:
        terraform_docs = f" Terraform provider docs: {', '.join(terraform_urls)}"
    rdbms_docs = ""
    if rdbms_urls:
        rdbms_docs = f" RDBMS docs: {', '.join(rdbms_urls)}"
    return f'AWS documentation evidence: "{quote}" ({url}) {detail}{terraform_properties}{terraform_docs}{rdbms_docs}'


def remediation_comment(evidence_key: str, evidence: dict[str, dict[str, object]]) -> str:
    """Build a Terraform remediation comment from evidence metadata."""
    item = evidence[evidence_key]
    terraform_urls = [str(url) for url in item.get("terraform_urls", [])]
    rdbms_urls = [str(url) for url in item.get("rdbms_urls", [])]
    properties = [str(prop) for prop in item.get("terraform_properties", [])]
    if not terraform_urls or not properties:
        return ""
    rdbms_docs = ""
    if rdbms_urls:
        rdbms_docs = f" RDBMS docs: {', '.join(rdbms_urls)}"
    return (
        "Terraform remediation: configure "
        f"{'; '.join(properties)}. Provider docs: {', '.join(terraform_urls)}{rdbms_docs}"
    )


def parameter_value(related: list[dict], name: str, default: object = None) -> object:
    """Return the value for an RDS or Aurora cluster parameter group parameter."""
    expected = name.lower()
    for group_type in ("aws_db_parameter_group", "aws_rds_cluster_parameter_group"):
        for resource in related:
            if resource.get("type") != group_type:
                continue
            for parameter in get_nested(resource, "values", "parameter", default=[]) or []:
                if str(get_nested(parameter, "name", default="")).lower() == expected:
                    return get_nested(parameter, "value", default=default)
    return default


def is_rds_cluster(resource: dict) -> bool:
    """Return whether *resource* is an Aurora/RDS cluster primary resource."""
    return resource.get("type") == "aws_rds_cluster"


def cluster_identifier(resource: dict) -> str:
    """Return the cluster identifier for an RDS cluster primary resource."""
    return str(
        get_nested(resource, "values", "cluster_identifier", default="")
        or get_nested(resource, "values", "id", default="")
    )


def cluster_instances(primary: dict, related: list[dict]) -> list[dict]:
    """Return cluster member instances related to an RDS cluster primary."""
    if not is_rds_cluster(primary):
        return []
    identifier = cluster_identifier(primary)
    instances = []
    for resource in related:
        if resource.get("type") != "aws_rds_cluster_instance":
            continue
        if str(get_nested(resource, "values", "cluster_identifier", default="")) == identifier:
            instances.append(resource)
    return instances


def option_names(related: list[dict]) -> set[str]:
    """Return configured option names from related RDS or Aurora option groups."""
    names = set()
    for group_type in ("aws_db_option_group", "aws_rds_cluster_option_group"):
        for resource in related:
            if resource.get("type") != group_type:
                continue
            for option in get_nested(resource, "values", "option", default=[]) or []:
                option_name = str(get_nested(option, "option_name", default="")).lower()
                if option_name:
                    names.add(option_name)
    return names


def engine_major_version(resource: dict) -> int | None:
    """Return parsed DB engine major version, if present."""
    version = str(get_nested(resource, "values", "engine_version", default=""))
    if not version:
        return None
    try:
        return int(version.split(".", 1)[0])
    except ValueError:
        return None
