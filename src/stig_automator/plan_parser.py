"""Terraform plan/state JSON parsing and resource discovery."""

from __future__ import annotations

import json
from fnmatch import fnmatch
from pathlib import Path

from .util import get_nested


def load_plan(path: Path) -> dict:
    """Read and parse a Terraform plan JSON file.

    Args:
        path: Filesystem path to the JSON file.

    Returns:
        Parsed plan as a dictionary.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def _format_instance_key(index_key: object) -> str:
    """Format a raw Terraform state instance key as an address suffix."""
    if index_key is None:
        return ""
    if isinstance(index_key, int):
        return f"[{index_key}]"
    return f"[{json.dumps(index_key)}]"


def _raw_state_address(resource: dict, instance: dict) -> str:
    """Build a Terraform address from raw state resource and instance data."""
    if instance.get("address"):
        return instance["address"]

    module = resource.get("module")
    base = f"{resource.get('type')}.{resource.get('name')}"
    if module:
        base = f"{module}.{base}"
    return f"{base}{_format_instance_key(instance.get('index_key'))}"


def walk_resources(plan: dict) -> list[dict]:
    """Walk Terraform plan/state JSON and return a flat list of all resources.

    Each resource dict is normalised to have ``address``, ``name``,
    ``type``, and ``values`` keys.  Searches plan and state value
    representations, raw Terraform state resources, and finally
    ``resource_changes``.

    Args:
        plan: Parsed Terraform plan dictionary.

    Returns:
        Flat list of resource dictionaries.
    """
    found: list[dict] = []

    def _walk_module(module: dict) -> None:
        for res in module.get("resources", []):
            found.append(res)
        for child in module.get("child_modules", []):
            _walk_module(child)

    for path in (
        ("planned_values", "root_module"),
        ("values", "root_module"),
        ("prior_state", "values", "root_module"),
        ("prior_state", "root_module"),
    ):
        root_module: dict | None = get_nested(plan, *path)
        if root_module:
            _walk_module(root_module)
            if found:
                return found

    for resource in plan.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        for instance in resource.get("instances", []):
            found.append({
                "address": _raw_state_address(resource, instance),
                "name": resource.get("name", "unknown"),
                "type": resource.get("type"),
                "values": instance.get("attributes") or {},
            })

    if not found:
        for rc in plan.get("resource_changes", []):
            after: dict = get_nested(rc, "change", "after") or {}
            found.append({
                "address": rc.get("address", rc.get("name", "unknown")),
                "name": rc.get("name", "unknown"),
                "type": rc.get("type"),
                "values": after,
            })

    return found


def filter_by_type(resources: list[dict], resource_type: str) -> list[dict]:
    """Return only resources matching *resource_type*.

    Args:
        resources: Flat list of resource dictionaries.
        resource_type: Terraform resource type string to match.

    Returns:
        Filtered list of resource dictionaries.
    """
    return [r for r in resources if r.get("type") == resource_type]


def filter_by_address(resources: list[dict], patterns: list[str]) -> list[dict]:
    """Return resources whose address matches any of the glob *patterns*.

    Args:
        resources: Flat list of resource dictionaries.
        patterns: Glob patterns to match against resource addresses.

    Returns:
        Filtered list of resource dictionaries.
    """
    return [
        r for r in resources
        if any(fnmatch(r.get("address", ""), p) for p in patterns)
    ]
