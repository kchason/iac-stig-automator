from stig_automator.models import CheckResult, Severity, StigControl


def _dummy_check(resource, related):
    return True, "ok"


class TestSeverity:
    def test_values(self):
        assert Severity.CAT_I.value == "CAT I (High)"
        assert Severity.CAT_II.value == "CAT II (Medium)"
        assert Severity.CAT_III.value == "CAT III (Low)"

    def test_is_str(self):
        assert isinstance(Severity.CAT_I, str)


class TestStigControl:
    def test_construction(self):
        c = StigControl(
            vuln_id="V-000001",
            stig_id="TEST-001",
            title="Test control",
            severity=Severity.CAT_I,
            description="A test.",
            check=_dummy_check,
        )
        assert c.vuln_id == "V-000001"
        assert c.severity == Severity.CAT_I
        assert c.csp_inherited is False


class TestCheckResult:
    def test_defaults(self):
        c = StigControl("V-1", "S-1", "T", Severity.CAT_II, "D", _dummy_check)
        r = CheckResult(control=c, met=True, detail="ok")
        assert r.not_applicable is False
