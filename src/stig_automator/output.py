"""Text, JSON, JUnit, and STIG Viewer cklb output renderers."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import TYPE_CHECKING
from uuid import NAMESPACE_URL, uuid5
from xml.etree import ElementTree as ET

from .models import CheckResult, Severity, StigControl

if TYPE_CHECKING:
    from .modules._base import BaseStigModule

SEV_ORDER: dict[Severity, int] = {Severity.CAT_I: 0, Severity.CAT_II: 1, Severity.CAT_III: 2}
CHECK_MET: str = "\u2705 MET"
CHECK_UNMET: str = "\u274c NOT MET"
CHECK_NA: str = "N/A NOT APPLICABLE"
MAX_FILENAME_STEM_LENGTH = 200
WINDOWS_RESERVED_FILENAMES: set[str] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}
UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_-]+")

_COLOR: dict[str, str] = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _c(text: str, *attrs: str, use_color: bool = True) -> str:
    """Wrap *text* in ANSI colour codes if *use_color* is ``True``.

    Args:
        text: The string to colour.
        *attrs: Colour/style names from ``_COLOR``.
        use_color: When ``False``, return *text* unchanged.

    Returns:
        Possibly ANSI-wrapped string.
    """
    if not use_color:
        return text
    codes: str = "".join(_COLOR[a] for a in attrs if a in _COLOR)
    return f"{codes}{text}{_COLOR['reset']}"


def render_text(
    report_title: str,
    resource: dict,
    results: list[CheckResult],
    verbose: bool,
    use_color: bool,
    include_recommendations: bool = False,
) -> str:
    """Render a human-readable text report for a single resource.

    Args:
        report_title: Header title (e.g. ``"AKS STIG Report"``).
        resource: Terraform resource dict with ``address`` / ``name``.
        results: Evaluated check results for this resource.
        verbose: Show descriptions for passing controls too.
        use_color: Emit ANSI colour codes.
        include_recommendations: Show corrective action guidance for open findings.

    Returns:
        Multi-line formatted report string.
    """
    name: str = resource.get("address") or resource.get("name", "unknown")
    lines: list[str] = []
    met: list[CheckResult] = [r for r in results if r.met and not r.not_applicable]
    not_applicable: list[CheckResult] = [r for r in results if r.not_applicable]
    not_met: list[CheckResult] = [r for r in results if not r.met and not r.not_applicable]

    header: str = f"{'=' * 72}\n  {report_title}: {name}\n{'=' * 72}"
    lines.append(_c(header, "bold", use_color=use_color))

    summary: str = (
        f"  Controls evaluated : {len(results)}\n"
        f"  Met                : {len(met)}\n"
        f"  Not Applicable     : {len(not_applicable)}\n"
        f"  Not Met            : {len(not_met)}\n"
        "  Score              : "
        f"{(len(met) + len(not_applicable)) / len(results) * 100:.1f}%"
    )
    lines.append(summary)

    for severity in (Severity.CAT_I, Severity.CAT_II, Severity.CAT_III):
        sev_results: list[CheckResult] = sorted(
            [r for r in results if r.control.severity == severity],
            key=lambda r: r.control.vuln_id,
        )
        if not sev_results:
            continue
        sev_header: str = f"\n  \u2500\u2500 {severity.value} Controls \u2500\u2500"
        lines.append(_c(sev_header, "bold", use_color=use_color))
        for r in sev_results:
            if r.not_applicable:
                status = CHECK_NA
                color = "yellow"
            else:
                status = CHECK_MET if r.met else CHECK_UNMET
                color = "green" if r.met else "red"
            lines.append(
                f"  {_c(status, color, use_color=use_color)}"
                f"  [{r.control.vuln_id}] {r.control.stig_id}"
                f"\n       {r.control.title}"
            )
            if verbose or not r.met or r.comments:
                lines.append(f"       Detail : {r.detail}")
                if r.comments:
                    lines.append(f"       Comments : {r.comments}")
                if include_recommendations and not r.met and not r.not_applicable:
                    corrective_action = _recommended_corrective_action(r.control)
                    if corrective_action:
                        lines.append(f"       Corrective Action : {corrective_action}")
                if verbose:
                    lines.append(f"       Desc   : {r.control.description}")

    lines.append("")
    return "\n".join(lines)


def render_json(resource: dict, results: list[CheckResult]) -> dict:
    """Render a machine-readable JSON report for a single resource.

    Args:
        resource: Terraform resource dict with ``address`` / ``name``.
        results: Evaluated check results for this resource.

    Returns:
        Dictionary suitable for ``json.dumps``.
    """
    name: str = resource.get("address") or resource.get("name", "unknown")
    met: list[CheckResult] = [r for r in results if r.met]
    return {
        "resource": name,
        "summary": {
            "total": len(results),
            "met": len(met),
            "not_met": len(results) - len(met),
            "score_pct": round(len(met) / len(results) * 100, 1),
        },
        "controls": [
            {
                "vuln_id": r.control.vuln_id,
                "stig_id": r.control.stig_id,
                "severity": r.control.severity.value,
                "title": r.control.title,
                "status": _result_to_json_status(r),
                "detail": r.detail,
                "comments": r.comments,
                "description": r.control.description,
            }
            for r in sorted(
                results,
                key=lambda x: (SEV_ORDER[x.control.severity], x.control.vuln_id),
            )
        ],
    }


def _result_to_cklb_status(result: CheckResult) -> str:
    """Map a CheckResult to a STIG Viewer cklb status string.

    Args:
        result: The check result to map.

    Returns:
        One of ``"not_a_finding"``, ``"open"``, or ``"not_applicable"``.
    """
    if result.not_applicable:
        return "not_applicable"
    return "not_a_finding" if result.met else "open"


def _result_to_json_status(result: CheckResult) -> str:
    if result.not_applicable:
        return "NOT_APPLICABLE"
    return "MET" if result.met else "NOT_MET"


def _result_to_junit_status(result: CheckResult) -> str:
    if result.not_applicable:
        return "not_applicable"
    return "not_a_finding" if result.met else "open"


def _junit_detail(result: CheckResult) -> str:
    lines = [
        f"Status: {_result_to_junit_status(result)}",
        f"Severity: {result.control.severity.value}",
        f"Detail: {result.detail}",
    ]
    if result.comments:
        lines.append(f"Comments: {result.comments}")
    return "\n".join(lines)


def render_junit(suites: list[tuple[str, dict, list[CheckResult]]]) -> str:
    """Render a consolidated JUnit XML report for evaluated resources.

    Args:
        suites: Tuples of ``(report_title, resource, results)``.

    Returns:
        XML string suitable for CI JUnit report ingestion.
    """
    total_tests = sum(len(results) for _title, _resource, results in suites)
    total_failures = sum(
        1
        for _title, _resource, results in suites
        for result in results
        if not result.met and not result.not_applicable
    )
    root = ET.Element(
        "testsuites",
        {
            "name": "stig-check",
            "tests": str(total_tests),
            "failures": str(total_failures),
            "errors": "0",
            "skipped": "0",
        },
    )

    for report_title, resource, results in suites:
        resource_name = str(resource.get("address") or resource.get("name") or "unknown")
        suite_failures = sum(
            1 for result in results if not result.met and not result.not_applicable
        )
        suite = ET.SubElement(
            root,
            "testsuite",
            {
                "name": f"{report_title}: {resource_name}",
                "tests": str(len(results)),
                "failures": str(suite_failures),
                "errors": "0",
                "skipped": "0",
            },
        )
        for result in sorted(
            results,
            key=lambda x: (SEV_ORDER[x.control.severity], x.control.vuln_id),
        ):
            status = _result_to_junit_status(result)
            case = ET.SubElement(
                suite,
                "testcase",
                {
                    "classname": f"{report_title}.{resource_name}",
                    "name": (
                        f"{result.control.vuln_id} {result.control.stig_id}: "
                        f"{result.control.title}"
                    ),
                    "time": "0",
                },
            )
            properties = ET.SubElement(case, "properties")
            for name, value in (
                ("resource", resource_name),
                ("vuln_id", result.control.vuln_id),
                ("stig_id", result.control.stig_id),
                ("severity", result.control.severity.value),
                ("status", status),
            ):
                ET.SubElement(properties, "property", {"name": name, "value": value})

            detail = _junit_detail(result)
            if status == "open":
                failure = ET.SubElement(
                    case,
                    "failure",
                    {
                        "message": (
                            f"{result.control.vuln_id} {result.control.stig_id} "
                            "is open"
                        ),
                        "type": "open",
                    },
                )
                failure.text = detail
            system_out = ET.SubElement(case, "system-out")
            system_out.text = detail

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def _first_text(*values: str) -> str:
    for value in values:
        if value:
            return value
    return ""


def _recommended_corrective_action(control: StigControl) -> str:
    """Return corrective action text with Terraform-specific remediation."""
    sections: list[str] = []
    if control.fix_text:
        sections.append(f"Recommended corrective action: {control.fix_text}")
    if control.remediation_comment:
        if control.fix_text:
            sections.append(control.remediation_comment)
        else:
            sections.append(f"Recommended corrective action: {control.remediation_comment}")
    return "\n".join(sections)


def _cklb_comments(result: CheckResult, *, include_recommendations: bool) -> str:
    """Return CKLB comments preserving reviewer text and remediation guidance."""
    comments: list[str] = []
    if result.comments:
        comments.append(result.comments)
    if include_recommendations and not result.met and not result.not_applicable:
        corrective_action = _recommended_corrective_action(result.control)
        if corrective_action:
            comments.append(corrective_action)
    return "\n".join(comments)


def _stable_uuid(*parts: str) -> str:
    return str(uuid5(NAMESPACE_URL, ":".join(parts)))


def _display_rule_id(control: StigControl) -> str:
    if control.rule_id:
        return control.rule_id
    if control.vuln_id.startswith("V-"):
        return f"SV-{control.vuln_id[2:]}_rule"
    return control.stig_id


def _cklb_rule_context(
    control: StigControl,
    *,
    stig_uuid: str,
    target_key: str,
    stig_ref: str,
    check_content_ref: dict,
    timestamp: str,
) -> dict:
    group_id = _first_text(control.group_id, control.vuln_id)
    rule_version = _first_text(control.rule_version, control.stig_id)
    rule_id = _display_rule_id(control)
    group_title = _first_text(control.group_title, control.title)
    check_content = _first_text(
        control.check_content,
        f"Static Terraform-plan evaluation for {rule_version}: {control.description}",
    )
    fix_text = _first_text(
        control.fix_text,
        f"Update the Terraform configuration so this resource satisfies: {control.title}",
    )

    return {
        "uuid": _stable_uuid(stig_uuid, group_id, rule_id),
        "stig_uuid": stig_uuid,
        "target_key": target_key,
        "stig_ref": stig_ref,
        "group_id": group_id,
        "rule_id": rule_id,
        "rule_id_src": rule_id,
        "weight": "10.0",
        "classification": "UNCLASSIFIED",
        "severity": {
            Severity.CAT_I: "high",
            Severity.CAT_II: "medium",
            Severity.CAT_III: "low",
        }[control.severity],
        "rule_version": rule_version,
        "group_title": group_title,
        "rule_title": control.title,
        "fix_text": fix_text,
        "false_positives": control.false_positives,
        "false_negatives": control.false_negatives,
        "discussion": control.description,
        "check_content": check_content,
        "documentable": control.documentable or "false",
        "mitigations": control.mitigations,
        "potential_impacts": control.potential_impacts,
        "third_party_tools": control.third_party_tools,
        "mitigation_control": control.mitigation_control,
        "responsibility": control.responsibility,
        "security_override_guidance": control.security_override_guidance,
        "ia_controls": ", ".join(control.cci),
        "check_content_ref": control.check_content_ref or check_content_ref,
        "legacy_ids": [],
        "group_tree": [
            {
                "id": group_id,
                "title": group_title,
                "description": "",
            },
        ],
        "createdAt": timestamp,
        "updatedAt": timestamp,
        "STIGUuid": stig_uuid,
        "overrides": {},
        "ccis": list(control.cci),
        "srg_id": group_title,
        # Backward-compatible aliases used by earlier stig-automator output.
        "group_id_src": group_id,
        "rule_ver": rule_version,
        "stig_id": rule_version,
        "title": control.title,
        "description": control.description,
        "vuln_discussion": control.description,
        "cci": list(control.cci),
    }


def render_cklb(
    module: BaseStigModule,
    resource: dict,
    results: list[CheckResult],
    *,
    host_name: str = "",
    target_comments: str = "Generated by stig-automator from Terraform plan analysis",
    include_recommendations: bool = False,
) -> dict:
    """Build a STIG Viewer 3.x ``.cklb`` document for a single resource.

    Args:
        module: The STIG module that was evaluated.
        resource: The Terraform resource dictionary.
        results: Check results for this resource.
        host_name: Optional hostname for ``target_data``.  Defaults to
            the Terraform resource address.
        target_comments: Comment text for the checklist target.
        include_recommendations: Add corrective action guidance to open findings.

    Returns:
        Dictionary representing the complete ``.cklb`` JSON document.
    """
    res_name: str = resource.get("address") or resource.get("name", "unknown")
    if not host_name:
        host_name = res_name

    now: str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    benchmark_id = module.stig_benchmark_id or module.name
    benchmark_title = module.stig_benchmark_title or module.report_title
    checklist_uuid = _stable_uuid("stig-automator", "checklist", benchmark_id, res_name)
    stig_uuid = _stable_uuid("stig-automator", "stig", benchmark_id)
    check_content_ref = {
        "href": f"{benchmark_id}.xml",
        "name": "M",
    }

    rules: list[dict] = []
    for r in sorted(
        results,
        key=lambda x: (SEV_ORDER[x.control.severity], x.control.vuln_id),
    ):
        rule = _cklb_rule_context(
            r.control,
            stig_uuid=stig_uuid,
            target_key=res_name,
            stig_ref=benchmark_title,
            check_content_ref=check_content_ref,
            timestamp=now,
        )
        rule.update({
            "status": _result_to_cklb_status(r),
            "finding_details": r.detail,
            "comments": _cklb_comments(r, include_recommendations=include_recommendations),
        })
        rules.append(rule)

    return {
        "title": benchmark_title,
        "id": checklist_uuid,
        "target_data": {
            "host_name": host_name[:255],
            "ip_address": "",
            "fqdn": "",
            "mac_address": "",
            "comments": target_comments,
            "role": "",
            "technology_area": "",
            "is_web_database": False,
            "web_db_site": "",
            "web_db_instance": "",
            "target_type": "Non-Computing",
        },
        "stigs": [
            {
                "stig_id": benchmark_id,
                "stig_name": benchmark_title,
                "display_name": benchmark_title,
                "version": module.stig_version,
                "release_info": module.stig_release_info,
                "uuid": stig_uuid,
                "reference_identifier": benchmark_id,
                "size": len(rules),
                "rules": rules,
            }
        ],
        "active": True,
        "mode": 1,
        "has_path": True,
        "evaluate-stig": {
            "time": now,
            "module": {
                "name": "stig-automator",
                "version": __import__("stig_automator").__version__,
            },
        },
        "cklb_version": "1.0",
    }


def resource_to_filename(resource: dict) -> str:
    """Derive a safe filename stem from a Terraform resource address.

    Non-portable filename characters are replaced with underscores so
    the result is usable as a filename on all platforms.

    Args:
        resource: Terraform resource dict with ``address`` / ``name``.

    Returns:
        Sanitised string suitable as a filename stem.
    """
    name: str = str(resource.get("address") or resource.get("name") or "unknown")
    stem = UNSAFE_FILENAME_CHARS.sub("_", name)
    stem = re.sub(r"_+", "_", stem).strip("_")
    stem = stem[:MAX_FILENAME_STEM_LENGTH].rstrip("_")
    if not stem:
        stem = "unknown"
    if stem.upper() in WINDOWS_RESERVED_FILENAMES:
        stem = f"resource_{stem}"
    return stem


class OutputPathAllocator:
    """Allocate stable, unique output filenames for resources."""

    def __init__(self) -> None:
        """Initialise empty resource-to-stem allocation state."""
        self._resource_stems: dict[int, str] = {}
        self._used_stems: set[str] = set()

    def filename_for(self, resource: dict, ext: str) -> str:
        """Return a de-duplicated filename for *resource* and *ext*."""
        return f"{self.stem_for(resource)}{ext}"

    def stem_for(self, resource: dict) -> str:
        """Return the de-duplicated filename stem assigned to *resource*."""
        resource_key = id(resource)
        if resource_key in self._resource_stems:
            return self._resource_stems[resource_key]

        base = resource_to_filename(resource)
        stem = base
        suffix = 2
        while stem.lower() in self._used_stems:
            stem = f"{base}_{suffix}"
            suffix += 1

        self._resource_stems[resource_key] = stem
        self._used_stems.add(stem.lower())
        return stem
