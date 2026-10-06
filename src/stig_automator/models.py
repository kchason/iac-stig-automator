"""Shared data models for STIG controls and check results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Severity(str, Enum):
    """DISA severity category for a STIG control."""

    CAT_I = "CAT I (High)"
    CAT_II = "CAT II (Medium)"
    CAT_III = "CAT III (Low)"


@dataclass
class StigControl:
    """Definition of a single STIG control and its automated check.

    Attributes:
        vuln_id: DISA vulnerability identifier (e.g. ``V-242381``).
        stig_id: STIG rule identifier (e.g. ``CNTR-K8-000370``).
        title: Short human-readable title.
        severity: DISA severity category.
        description: Long-form explanation of the requirement.
        check: Callable ``(resource, related) -> (met, detail)`` or
            ``(met, detail, not_applicable)`` that evaluates whether the
            control is satisfied.
        csp_inherited: Whether the cloud service provider supplies the
            control evidence without Terraform plan input.
        group_id: Display group identifier for checklist exports.
        rule_id: Source rule identifier for checklist exports.
        rule_version: Stable STIG rule version identifier.
        group_title: Group title shown by checklist viewers.
        check_content: Manual check text shown by checklist viewers.
        fix_text: Remediation text shown by checklist viewers.
        cci: CCI references associated with the control.
        false_positives: Official STIG false positive text.
        false_negatives: Official STIG false negative text.
        documentable: Official STIG documentable flag text.
        mitigations: Official STIG mitigation text.
        potential_impacts: Official STIG potential impact text.
        third_party_tools: Official STIG third-party tool text.
        mitigation_control: Official STIG mitigation control text.
        responsibility: Official STIG responsibility text.
        security_override_guidance: Official STIG security override guidance.
        check_content_ref: Official STIG check content reference metadata.
        remediation_comment: Terraform-specific comment for open findings.
    """

    vuln_id: str
    stig_id: str
    title: str
    severity: Severity
    description: str
    check: Callable[[dict, list[dict]], tuple[bool, str] | tuple[bool, str, bool]] = field(repr=False)
    csp_inherited: bool = False
    group_id: str = ""
    rule_id: str = ""
    rule_version: str = ""
    group_title: str = ""
    check_content: str = ""
    fix_text: str = ""
    cci: tuple[str, ...] = ()
    false_positives: str = ""
    false_negatives: str = ""
    documentable: str = ""
    mitigations: str = ""
    potential_impacts: str = ""
    third_party_tools: str = ""
    mitigation_control: str = ""
    responsibility: str = ""
    security_override_guidance: str = ""
    check_content_ref: dict[str, str] = field(default_factory=dict)
    remediation_comment: str = ""


@dataclass
class CheckResult:
    """Outcome of evaluating a single STIG control against a resource.

    Attributes:
        control: The control that was evaluated.
        met: Whether the control requirement is satisfied.
        detail: Explanation or evidence string.
        not_applicable: ``True`` when the control does not apply.
        comments: Reviewer comments associated with the control result.
    """

    control: StigControl
    met: bool
    detail: str
    not_applicable: bool = False
    comments: str = ""
