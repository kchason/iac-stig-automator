from xml.etree import ElementTree as ET

from stig_automator.models import CheckResult, Severity, StigControl
from stig_automator.output import (
    OutputPathAllocator,
    render_cklb,
    render_json,
    render_junit,
    render_text,
    resource_to_filename,
)
from stig_automator.registry import get_module

import stig_automator.modules  # noqa: F401


def _make_result(
    vuln_id,
    met,
    severity=Severity.CAT_II,
    fix_text="",
    remediation_comment="",
    not_applicable=False,
):
    ctrl = StigControl(
        vuln_id=vuln_id,
        stig_id=f"STIG-{vuln_id}",
        title=f"Title for {vuln_id}",
        severity=severity,
        description=f"Desc for {vuln_id}",
        check=lambda r, rel: (met, "detail"),
        fix_text=fix_text,
        remediation_comment=remediation_comment,
    )
    return CheckResult(
        control=ctrl,
        met=met,
        detail="test detail",
        not_applicable=not_applicable,
    )


class TestRenderText:
    def test_contains_report_title(self):
        resource = {"address": "test.resource"}
        results = [_make_result("V-1", True)]
        text = render_text("My Report", resource, results, verbose=False, use_color=False)
        assert "My Report: test.resource" in text

    def test_score(self):
        resource = {"address": "test.resource"}
        results = [_make_result("V-1", True), _make_result("V-2", False)]
        text = render_text("Report", resource, results, verbose=False, use_color=False)
        assert "50.0%" in text

    def test_no_color(self):
        resource = {"address": "test.resource"}
        results = [_make_result("V-1", True)]
        text = render_text("Report", resource, results, verbose=False, use_color=False)
        assert "\033[" not in text

    def test_verbose_shows_description(self):
        resource = {"address": "test.resource"}
        results = [_make_result("V-1", True)]
        text = render_text("Report", resource, results, verbose=True, use_color=False)
        assert "Desc for V-1" in text

    def test_non_verbose_hides_description_for_met(self):
        resource = {"address": "test.resource"}
        results = [_make_result("V-1", True)]
        text = render_text("Report", resource, results, verbose=False, use_color=False)
        assert "Desc for V-1" not in text

    def test_failing_control_always_shows_detail(self):
        resource = {"address": "test.resource"}
        results = [_make_result("V-1", False)]
        text = render_text("Report", resource, results, verbose=False, use_color=False)
        assert "test detail" in text

    def test_failing_control_hides_corrective_action_by_default(self):
        resource = {"address": "test.resource"}
        results = [
            _make_result(
                "V-1",
                False,
                fix_text="Set the secure transport requirement.",
                remediation_comment=(
                    "Terraform remediation: configure "
                    "azurerm_mysql_flexible_server_configuration.name = "
                    "\"require_secure_transport\", value = \"ON\"."
                ),
            ),
        ]
        text = render_text("Report", resource, results, verbose=False, use_color=False)
        assert "Corrective Action" not in text

    def test_failing_control_shows_corrective_action_when_enabled(self):
        resource = {"address": "test.resource"}
        results = [
            _make_result(
                "V-1",
                False,
                fix_text="Set the secure transport requirement.",
                remediation_comment=(
                    "Terraform remediation: configure "
                    "azurerm_mysql_flexible_server_configuration.name = "
                    "\"require_secure_transport\", value = \"ON\"."
                ),
            ),
        ]
        text = render_text(
            "Report",
            resource,
            results,
            verbose=False,
            use_color=False,
            include_recommendations=True,
        )
        assert (
            "Corrective Action : Recommended corrective action: "
            "Set the secure transport requirement."
        ) in text
        assert "azurerm_mysql_flexible_server_configuration.name" in text
        assert 'value = "ON"' in text


class TestRenderJson:
    def test_structure(self):
        resource = {"address": "test.resource"}
        results = [_make_result("V-1", True), _make_result("V-2", False)]
        data = render_json(resource, results)
        assert data["resource"] == "test.resource"
        assert data["summary"]["total"] == 2
        assert data["summary"]["met"] == 1
        assert data["summary"]["not_met"] == 1
        assert data["summary"]["score_pct"] == 50.0
        assert len(data["controls"]) == 2

    def test_controls_sorted_by_severity(self):
        resource = {"address": "test.resource"}
        results = [
            _make_result("V-3", True, Severity.CAT_III),
            _make_result("V-1", True, Severity.CAT_I),
            _make_result("V-2", True, Severity.CAT_II),
        ]
        data = render_json(resource, results)
        severities = [c["severity"] for c in data["controls"]]
        assert severities == ["CAT I (High)", "CAT II (Medium)", "CAT III (Low)"]


class TestRenderJunit:
    def test_open_controls_are_failures_and_other_statuses_pass(self):
        resource = {"address": "test.resource"}
        results = [
            _make_result("V-1", True),
            _make_result("V-2", False),
            _make_result("V-3", True, not_applicable=True),
        ]

        root = ET.fromstring(render_junit([("Report", resource, results)]))
        cases = root.findall(".//testcase")
        failures = root.findall(".//failure")
        statuses = {
            prop.attrib["value"]
            for prop in root.findall(".//property[@name='status']")
        }

        assert root.attrib["tests"] == "3"
        assert root.attrib["failures"] == "1"
        assert len(cases) == 3
        assert len(failures) == 1
        assert statuses == {"not_a_finding", "open", "not_applicable"}
        assert "Status: open" in failures[0].text

    def test_multiple_resources_render_as_separate_suites(self):
        suites = [
            ("Report", {"address": "resource.one"}, [_make_result("V-1", True)]),
            ("Report", {"address": "resource.two"}, [_make_result("V-2", False)]),
        ]

        root = ET.fromstring(render_junit(suites))
        suite_names = [suite.attrib["name"] for suite in root.findall("testsuite")]

        assert root.attrib["tests"] == "2"
        assert root.attrib["failures"] == "1"
        assert suite_names == [
            "Report: resource.one",
            "Report: resource.two",
        ]


class TestRenderCklb:
    def test_top_level_structure(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        results = [_make_result("V-1", True), _make_result("V-2", False)]
        doc = render_cklb(mod, resource, results)
        assert "target_data" in doc
        assert "stigs" in doc
        assert "evaluate-stig" in doc
        assert doc["target_data"]["host_name"] == "test.cluster"

    def test_custom_host_name(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        results = [_make_result("V-1", True)]
        doc = render_cklb(mod, resource, results, host_name="my-host")
        assert doc["target_data"]["host_name"] == "my-host"

    def test_stig_metadata(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        results = [_make_result("V-1", True)]
        doc = render_cklb(mod, resource, results)
        stig = doc["stigs"][0]
        assert stig["stig_id"] == mod.stig_benchmark_id
        assert stig["version"] == mod.stig_version
        assert stig["release_info"] == mod.stig_release_info

    def test_rule_statuses(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        results = [_make_result("V-1", True), _make_result("V-2", False)]
        doc = render_cklb(mod, resource, results)
        rules = doc["stigs"][0]["rules"]
        statuses = {r["group_id"]: r["status"] for r in rules}
        assert statuses["V-1"] == "not_a_finding"
        assert statuses["V-2"] == "open"

    def test_open_comments_omit_corrective_action_by_default(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        result = _make_result(
            "V-1",
            False,
            remediation_comment=(
                "Terraform remediation: configure "
                "azurerm_postgresql_flexible_server_configuration.name = "
                "\"password_encryption\", value = \"scram-sha-256\"."
            ),
        )
        doc = render_cklb(mod, resource, [result])
        assert doc["stigs"][0]["rules"][0]["comments"] == ""

    def test_open_comments_include_corrective_action_when_enabled(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        result = _make_result(
            "V-1",
            False,
            fix_text="Enable the required server setting.",
            remediation_comment=(
                "Terraform remediation: configure "
                "azurerm_postgresql_flexible_server_configuration.name = "
                "\"password_encryption\", value = \"scram-sha-256\"."
            ),
        )
        doc = render_cklb(mod, resource, [result], include_recommendations=True)
        comments = doc["stigs"][0]["rules"][0]["comments"]
        assert "Recommended corrective action: Enable the required server setting." in comments
        assert "azurerm_postgresql_flexible_server_configuration.name" in comments
        assert 'value = "scram-sha-256"' in comments

    def test_open_comments_preserve_reviewer_comments(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        result = _make_result(
            "V-1",
            False,
            remediation_comment=(
                "Terraform remediation: configure "
                "azurerm_kubernetes_cluster.azure_policy_enabled = true."
            ),
        )
        result.comments = "Reviewed manually and remains open."
        doc = render_cklb(mod, resource, [result], include_recommendations=True)
        comments = doc["stigs"][0]["rules"][0]["comments"]
        assert "Reviewed manually and remains open." in comments
        assert "azurerm_kubernetes_cluster.azure_policy_enabled" in comments

    def test_not_applicable_status(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        ctrl = StigControl("V-1", "S-1", "T", Severity.CAT_II, "D", lambda r, rel: (True, "ok"))
        result = CheckResult(control=ctrl, met=True, detail="N/A", not_applicable=True)
        doc = render_cklb(mod, resource, [result])
        assert doc["stigs"][0]["rules"][0]["status"] == "not_applicable"

    def test_rule_severity_mapping(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        results = [
            _make_result("V-1", True, Severity.CAT_I),
            _make_result("V-2", True, Severity.CAT_II),
            _make_result("V-3", True, Severity.CAT_III),
        ]
        doc = render_cklb(mod, resource, results)
        rules = doc["stigs"][0]["rules"]
        severity_map = {r["group_id"]: r["severity"] for r in rules}
        assert severity_map["V-1"] == "high"
        assert severity_map["V-2"] == "medium"
        assert severity_map["V-3"] == "low"

    def test_rule_context_fields(self):
        mod = get_module("aks")
        resource = {"address": "test.cluster"}
        result = _make_result("V-1", True)
        doc = render_cklb(mod, resource, [result])
        rule = doc["stigs"][0]["rules"][0]
        stig = doc["stigs"][0]
        assert doc["id"]
        assert doc["active"] is True
        assert doc["mode"] == 1
        assert doc["has_path"] is True
        assert doc["cklb_version"] == "1.0"
        assert stig["uuid"]
        assert stig["display_name"] == mod.stig_benchmark_title
        assert stig["reference_identifier"] == mod.stig_benchmark_id
        assert stig["size"] == 1
        assert rule["uuid"]
        assert rule["stig_uuid"] == stig["uuid"]
        assert rule["STIGUuid"] == stig["uuid"]
        assert rule["target_key"] == "test.cluster"
        assert rule["stig_ref"] == mod.stig_benchmark_title
        assert rule["group_id"] == "V-1"
        assert rule["group_id_src"] == "V-1"
        assert rule["rule_id"] == "SV-1_rule"
        assert rule["rule_id_src"] == "SV-1_rule"
        assert rule["rule_version"] == "STIG-V-1"
        assert rule["rule_ver"] == "STIG-V-1"
        assert rule["group_title"] == "Title for V-1"
        assert rule["rule_title"] == "Title for V-1"
        assert "Desc for V-1" in rule["discussion"]
        assert "Desc for V-1" in rule["check_content"]
        assert "Title for V-1" in rule["fix_text"]
        assert rule["check_content_ref"]["name"] == "M"
        assert rule["group_tree"][0]["id"] == "V-1"
        assert rule["overrides"] == {}


class TestResourceToFilename:
    def test_dots_replaced(self):
        assert resource_to_filename({"address": "a.b.c"}) == "a_b_c"

    def test_slashes_replaced(self):
        assert resource_to_filename({"address": "module/a.b"}) == "module_a_b"

    def test_fallback_to_name(self):
        assert resource_to_filename({"name": "foo"}) == "foo"

    def test_special_characters_removed_from_path_stem(self):
        resource = {"address": 'module.db.azurerm_resource.example["prod/us:east*1?"]'}
        assert resource_to_filename(resource) == "module_db_azurerm_resource_example_prod_us_east_1"

    def test_empty_or_reserved_stems_use_safe_fallback(self):
        assert resource_to_filename({"address": '"/\\:*?"'}) == "unknown"
        assert resource_to_filename({"address": "CON"}) == "resource_CON"


class TestOutputPathAllocator:
    def test_deduplicates_sanitized_filename_collisions(self):
        allocator = OutputPathAllocator()
        slash_resource = {"address": "a/b"}
        colon_resource = {"address": "a:b"}
        literal_resource = {"address": "a_b"}

        assert allocator.filename_for(slash_resource, ".json") == "a_b.json"
        assert allocator.filename_for(colon_resource, ".json") == "a_b_2.json"
        assert allocator.filename_for(literal_resource, ".json") == "a_b_3.json"
        assert allocator.filename_for(slash_resource, ".cklb") == "a_b.cklb"
