"""Manual control status overrides loaded from JSON."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import CheckResult


STATUS_NOT_A_FINDING = "Not a Finding"
STATUS_OPEN = "Open"
STATUS_NOT_APPLICABLE = "Not Applicable"

_STATUS_ALIASES = {
    "not a finding": STATUS_NOT_A_FINDING,
    "not_a_finding": STATUS_NOT_A_FINDING,
    "not-a-finding": STATUS_NOT_A_FINDING,
    "open": STATUS_OPEN,
    "not applicable": STATUS_NOT_APPLICABLE,
    "not_applicable": STATUS_NOT_APPLICABLE,
    "not-applicable": STATUS_NOT_APPLICABLE,
}


@dataclass(frozen=True)
class ManualOverride:
    """A reviewer-supplied override for one control ID."""

    control_id: str
    status: str
    comments: str = ""
    details: str = ""


def _get_field(entry: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in entry.items()}
    for name in names:
        if name in entry:
            return entry[name]
        value = lowered.get(name.lower())
        if value is not None:
            return value
    return None


def _normalise_status(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return _STATUS_ALIASES.get(value.strip().lower())


def parse_manual_overrides(data: Any) -> tuple[list[ManualOverride], list[str]]:
    """Parse manual control overrides from decoded JSON data.

    Args:
        data: Decoded JSON. Expected to be a list of entries or an object with
            a ``controls`` list.

    Returns:
        A tuple of valid overrides and warning messages for skipped entries.
    """
    if isinstance(data, dict) and isinstance(data.get("controls"), list):
        entries = data["controls"]
    elif isinstance(data, list):
        entries = data
    else:
        return [], [
            "manual controls JSON must be a list or an object with a controls list"
        ]

    warnings: list[str] = []
    overrides: list[ManualOverride] = []
    seen: set[str] = set()

    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            warnings.append(f"manual controls entry {index} is not an object; skipping")
            continue

        control_id = _get_field(entry, "Control ID", "control_id", "controlId", "id")
        status = _normalise_status(_get_field(entry, "Status", "status"))
        comments = _get_field(entry, "Comments", "comments", "comment")
        details = _get_field(
            entry,
            "Details",
            "details",
            "Detail",
            "detail",
            "Finding Details",
            "finding_details",
            "findingDetails",
        )

        if not isinstance(control_id, str) or not control_id.strip():
            warnings.append(f"manual controls entry {index} is missing Control ID; skipping")
            continue
        if status is None:
            warnings.append(
                f"manual controls entry {index} for {control_id!r} "
                "has unsupported Status; skipping"
            )
            continue

        clean_control_id = control_id.strip()
        if clean_control_id in seen:
            warnings.append(
                f"manual controls entry {index} duplicates {clean_control_id}; "
                "using the last value"
            )
        seen.add(clean_control_id)
        overrides.append(
            ManualOverride(
                clean_control_id,
                status,
                "" if comments is None else str(comments),
                "" if details is None else str(details),
            )
        )

    return overrides, warnings


def apply_manual_overrides(
    results: list[CheckResult],
    overrides: dict[str, ManualOverride],
) -> set[str]:
    """Apply manual overrides to evaluated results.

    Args:
        results: Results produced by automated controls.
        overrides: Overrides keyed by control ID.

    Returns:
        Control IDs that matched at least one result.
    """
    matched: set[str] = set()
    for result in results:
        override = overrides.get(result.control.vuln_id) or overrides.get(
            result.control.stig_id
        )
        if override is None:
            continue

        matched.add(override.control_id)
        result.comments = override.comments
        if override.details.strip():
            result.detail = override.details.strip()
        if override.status == STATUS_NOT_A_FINDING:
            result.met = True
            result.not_applicable = False
        elif override.status == STATUS_OPEN:
            result.met = False
            result.not_applicable = False
        elif override.status == STATUS_NOT_APPLICABLE:
            result.met = True
            result.not_applicable = True

    return matched
