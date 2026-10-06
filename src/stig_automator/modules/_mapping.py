"""Shared helpers for JSON-driven control behavior mappings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping


CheckCallable = Callable[[dict, list[dict]], tuple[bool, str] | tuple[bool, str, bool]]
DetailBuilder = Callable[["ControlMapping", dict, list[dict]], str]

ALLOWED_CKLB_STATUSES = {"not_a_finding", "open", "not_applicable"}


@dataclass(frozen=True)
class ControlMapping:
    """Validated JSON mapping for one control's local evaluation behavior."""

    control_id: str
    automatic_platform_text: str = ""
    validation_function_name: str = ""
    evidence_key: str = ""
    remediation_key: str = ""
    cklb_status: str = ""
    include_in_blank_cklb: bool = False

    @property
    def is_platform(self) -> bool:
        """Return whether this mapping uses static platform evidence text."""
        return bool(self.automatic_platform_text)

    @property
    def is_validation(self) -> bool:
        """Return whether this mapping points at a validation callback."""
        return bool(self.validation_function_name)


@dataclass(frozen=True)
class ControlMappings:
    """Collection of explicit control mappings and an optional default."""

    controls: dict[str, ControlMapping]
    default: ControlMapping | None = None

    def for_control(self, control_id: str) -> ControlMapping:
        """Return the explicit mapping for *control_id*, or the default mapping."""
        mapping = self.controls.get(control_id)
        if mapping is not None:
            return mapping
        if self.default is not None:
            return ControlMapping(
                control_id=control_id,
                automatic_platform_text=self.default.automatic_platform_text,
                validation_function_name=self.default.validation_function_name,
                evidence_key=self.default.evidence_key,
                remediation_key=self.default.remediation_key,
                cklb_status=self.default.cklb_status,
                include_in_blank_cklb=self.default.include_in_blank_cklb,
            )
        raise KeyError(f"No control mapping defined for {control_id}")


def _require_string(data: Mapping[str, object], key: str, control_id: str) -> str:
    value = data.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{control_id}: {key} must be a string")
    return value


def _require_bool(data: Mapping[str, object], key: str, control_id: str) -> bool:
    value = data.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{control_id}: {key} must be true or false")
    return value


def _parse_mapping(
    control_id: str,
    data: Mapping[str, object],
    *,
    module_name: str,
    validation_functions: Mapping[str, CheckCallable],
    evidence_keys: set[str] | None,
) -> ControlMapping:
    automatic_platform_text = _require_string(data, "automatic_platform_text", control_id)
    validation_function_name = _require_string(data, "validation_function_name", control_id)
    if bool(automatic_platform_text) == bool(validation_function_name):
        raise ValueError(
            f"{module_name} {control_id}: define exactly one of "
            "automatic_platform_text or validation_function_name",
        )

    evidence_key = _require_string(data, "evidence_key", control_id)
    remediation_key = _require_string(data, "remediation_key", control_id)
    cklb_status = _require_string(data, "cklb_status", control_id)
    include_in_blank_cklb = _require_bool(data, "include_in_blank_cklb", control_id)

    if validation_function_name and validation_function_name not in validation_functions:
        raise ValueError(
            f"{module_name} {control_id}: unknown validation_function_name "
            f"{validation_function_name!r}",
        )
    if validation_function_name and include_in_blank_cklb:
        raise ValueError(
            f"{module_name} {control_id}: validation controls cannot be included in blank CKLB output",
        )
    if automatic_platform_text:
        if cklb_status not in ALLOWED_CKLB_STATUSES:
            raise ValueError(
                f"{module_name} {control_id}: cklb_status must be one of "
                f"{', '.join(sorted(ALLOWED_CKLB_STATUSES))}",
            )
    elif cklb_status:
        raise ValueError(f"{module_name} {control_id}: cklb_status is only valid for platform mappings")

    if evidence_keys is not None:
        for key_name, key_value in (
            ("evidence_key", evidence_key),
            ("remediation_key", remediation_key),
        ):
            if key_value and key_value not in evidence_keys:
                raise ValueError(f"{module_name} {control_id}: unknown {key_name} {key_value!r}")

    return ControlMapping(
        control_id=control_id,
        automatic_platform_text=automatic_platform_text,
        validation_function_name=validation_function_name,
        evidence_key=evidence_key,
        remediation_key=remediation_key,
        cklb_status=cklb_status,
        include_in_blank_cklb=include_in_blank_cklb,
    )


def load_control_mappings(
    data: Mapping[str, object],
    *,
    module_name: str,
    validation_functions: Mapping[str, CheckCallable],
    evidence_keys: set[str] | None = None,
) -> ControlMappings:
    """Validate and return control mappings loaded from JSON."""
    raw_controls = data.get("controls")
    if not isinstance(raw_controls, dict):
        raise ValueError(f"{module_name}: mappings JSON must contain a controls object")

    default = None
    raw_default = data.get("default")
    if raw_default is not None:
        if not isinstance(raw_default, dict):
            raise ValueError(f"{module_name}: default mapping must be an object")
        default = _parse_mapping(
            "<default>",
            raw_default,
            module_name=module_name,
            validation_functions=validation_functions,
            evidence_keys=evidence_keys,
        )

    controls: dict[str, ControlMapping] = {}
    for control_id, raw_mapping in raw_controls.items():
        if not isinstance(control_id, str):
            raise ValueError(f"{module_name}: control IDs must be strings")
        if not isinstance(raw_mapping, dict):
            raise ValueError(f"{module_name} {control_id}: mapping must be an object")
        controls[control_id] = _parse_mapping(
            control_id,
            raw_mapping,
            module_name=module_name,
            validation_functions=validation_functions,
            evidence_keys=evidence_keys,
        )

    return ControlMappings(controls=controls, default=default)


def result_flags_for_cklb_status(status: str) -> tuple[bool, bool]:
    """Return ``(met, not_applicable)`` for a cklb status value."""
    if status == "not_a_finding":
        return True, False
    if status == "open":
        return False, False
    if status == "not_applicable":
        return True, True
    raise ValueError(f"Unsupported cklb_status {status!r}")


def make_platform_check(mapping: ControlMapping, detail_builder: DetailBuilder) -> CheckCallable:
    """Build a check function backed by static platform evidence text."""

    def _check(resource: dict, related: list[dict]) -> tuple[bool, str, bool]:
        met, not_applicable = result_flags_for_cklb_status(mapping.cklb_status)
        return met, detail_builder(mapping, resource, related), not_applicable

    return _check
