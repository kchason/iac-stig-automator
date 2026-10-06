from stig_automator.manual_overrides import apply_manual_overrides, parse_manual_overrides
from stig_automator.models import CheckResult, Severity, StigControl


def _result(vuln_id="V-1", stig_id="STIG-1", met=False):
    control = StigControl(
        vuln_id=vuln_id,
        stig_id=stig_id,
        title="Title",
        severity=Severity.CAT_II,
        description="Description",
        check=lambda r, rel: (met, "detail"),
    )
    return CheckResult(control=control, met=met, detail="automated detail")


class TestParseManualOverrides:
    def test_parses_list_with_expected_fields(self):
        overrides, warnings = parse_manual_overrides([
            {
                "Control ID": "V-1",
                "Status": "Not a Finding",
                "Comments": "Reviewed manually",
                "Details": "Reviewer-supplied evidence",
            },
        ])

        assert warnings == []
        assert len(overrides) == 1
        assert overrides[0].control_id == "V-1"
        assert overrides[0].status == "Not a Finding"
        assert overrides[0].comments == "Reviewed manually"
        assert overrides[0].details == "Reviewer-supplied evidence"

    def test_parses_controls_wrapper(self):
        overrides, warnings = parse_manual_overrides({
            "controls": [
                {
                    "control_id": "STIG-1",
                    "status": "not_applicable",
                    "comments": "N/A",
                },
            ],
        })

        assert warnings == []
        assert overrides[0].control_id == "STIG-1"
        assert overrides[0].status == "Not Applicable"

    def test_warns_for_bad_status(self):
        overrides, warnings = parse_manual_overrides([
            {"Control ID": "V-1", "Status": "Closed", "Comments": ""},
        ])

        assert overrides == []
        assert "unsupported Status" in warnings[0]

    def test_warns_for_bad_shape(self):
        overrides, warnings = parse_manual_overrides({"not_controls": []})

        assert overrides == []
        assert "manual controls JSON must be a list" in warnings[0]


class TestApplyManualOverrides:
    def test_applies_open_by_vuln_id(self):
        result = _result(met=True)
        overrides, _warnings = parse_manual_overrides([
            {"Control ID": "V-1", "Status": "Open", "Comments": "Still open"},
        ])

        matched = apply_manual_overrides([result], {o.control_id: o for o in overrides})

        assert matched == {"V-1"}
        assert result.met is False
        assert result.not_applicable is False
        assert result.comments == "Still open"

    def test_applies_not_applicable_by_stig_id(self):
        result = _result()
        overrides, _warnings = parse_manual_overrides([
            {
                "Control ID": "STIG-1",
                "Status": "Not Applicable",
                "Comments": "Out of scope",
            },
        ])

        matched = apply_manual_overrides([result], {o.control_id: o for o in overrides})

        assert matched == {"STIG-1"}
        assert result.met is True
        assert result.not_applicable is True
        assert result.comments == "Out of scope"

    def test_populated_details_replace_result_detail(self):
        result = _result()
        overrides, _warnings = parse_manual_overrides([
            {
                "Control ID": "V-1",
                "Status": "Open",
                "Comments": "Reviewer comment",
                "Details": "Reviewer finding details",
            },
        ])

        apply_manual_overrides([result], {o.control_id: o for o in overrides})

        assert result.detail == "Reviewer finding details"

    def test_empty_details_preserve_result_detail(self):
        result = _result()
        overrides, _warnings = parse_manual_overrides([
            {
                "Control ID": "V-1",
                "Status": "Open",
                "Comments": "Reviewer comment",
                "Details": "  ",
            },
        ])

        apply_manual_overrides([result], {o.control_id: o for o in overrides})

        assert result.detail == "automated detail"
