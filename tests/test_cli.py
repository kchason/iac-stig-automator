from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest


REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = Path(__file__).parent / "fixtures"
PLAN_FIXTURES = sorted(FIXTURES_DIR.glob("*_sample_plan.json"))
PLAN_STATE_FIXTURES = [
    (plan_path, plan_path.with_name(plan_path.name.replace("_plan", "_state")))
    for plan_path in PLAN_FIXTURES
]


def run_cli(
    *args: str,
    input_data: str | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    src_path = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = (
        src_path if not env.get("PYTHONPATH") else f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
    )
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "stig_automator.cli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        input=input_data,
        cwd=cwd or REPO_ROOT,
        env=env,
    )


class TestListModules:
    def test_lists_aks(self):
        result = run_cli("--list-modules")
        assert result.returncode == 0
        assert "aks" in result.stdout
        assert "mysql_flexible" in result.stdout
        assert "postgres_flexible" in result.stdout

    def test_shows_resource_type(self):
        result = run_cli("--list-modules")
        assert "azurerm_kubernetes_cluster" in result.stdout
        assert "azurerm_postgresql_flexible_server" in result.stdout

    def test_help_states_results_are_not_accreditation_evidence(self):
        result = run_cli("--help")
        assert result.returncode == 0
        assert "not authorization, accreditation, or audit evidence" in result.stdout


class TestTextOutput:
    def test_aks_text_output(self):
        result = run_cli(str(FIXTURES_DIR / "aks_sample_plan.json"))
        assert result.returncode == 1
        assert "AKS STIG Report" in result.stdout

    @pytest.mark.parametrize(
        "plan_path,state_path",
        PLAN_STATE_FIXTURES,
        ids=[plan_path.name for plan_path, _state_path in PLAN_STATE_FIXTURES],
    )
    def test_plan_and_state_json_text_output_match(self, plan_path, state_path):
        plan_result = run_cli(str(plan_path), "--no-color")
        state_result = run_cli(str(state_path), "--no-color")

        assert state_result.returncode == plan_result.returncode
        assert state_result.stdout == plan_result.stdout
        assert "No resources found matching the given criteria." not in state_result.stderr

    def test_mysql_text_output(self):
        result = run_cli(str(FIXTURES_DIR / "mysql_sample_plan.json"))
        assert result.returncode == 1
        assert "MySQL Flexible Server STIG Report" in result.stdout

    def test_postgres_text_output(self):
        result = run_cli(str(FIXTURES_DIR / "postgres_sample_plan.json"))
        assert result.returncode == 1
        assert "Azure PostgreSQL Flexible Server STIG Report" in result.stdout

    def test_resource_filter_keeps_related_postgres_resources(self):
        result = run_cli(
            str(FIXTURES_DIR / "postgres_sample_plan.json"),
            "-m", "postgres_flexible",
            "-r", "azurerm_postgresql_flexible_server.compliant",
            "--no-color",
        )
        assert result.returncode == 0
        assert "Met                : 85" in result.stdout
        assert "Not Applicable     : 26" in result.stdout

    def test_verbose_output(self):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"), "-v", "--no-color"
        )
        assert "Desc" in result.stdout

    def test_no_color(self):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"), "--no-color"
        )
        assert "\033[" not in result.stdout

    def test_default_is_text(self):
        result = run_cli(str(FIXTURES_DIR / "aks_sample_plan.json"), "--no-color")
        assert "AKS STIG Report" in result.stdout

    def test_text_output_includes_terraform_corrective_action(self):
        result = run_cli(
            str(FIXTURES_DIR / "mysql_sample_plan.json"),
            "-m", "mysql_flexible",
            "-r", "azurerm_mysql_flexible_server.non_compliant",
            "--recommendations",
            "--no-color",
        )
        assert result.returncode == 1
        assert "Corrective Action : Recommended corrective action:" in result.stdout
        assert "Terraform remediation: configure" in result.stdout
        assert "azurerm_mysql_flexible_server_configuration.name" in result.stdout
        assert "DML" in result.stdout

    def test_text_output_hides_terraform_corrective_action_by_default(self):
        result = run_cli(
            str(FIXTURES_DIR / "mysql_sample_plan.json"),
            "-m", "mysql_flexible",
            "-r", "azurerm_mysql_flexible_server.non_compliant",
            "--no-color",
        )
        assert result.returncode == 1
        assert "Corrective Action" not in result.stdout


class TestBlankOutput:
    def test_blank_text_does_not_require_plan_file(self):
        result = run_cli("--blank", "-m", "aks", "--no-color")
        assert result.returncode == 0
        assert "AKS STIG Report: aks.csp_inherited_controls" in result.stdout
        assert "NOT MET" not in result.stdout

    def test_blank_json_writes_only_csp_inherited_controls(self, tmp_path):
        result = run_cli(
            "--blank",
            "-m", "aks",
            "-o", "json",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 0
        json_files = list(tmp_path.glob("*.json"))
        assert [f.name for f in json_files] == ["aks_csp_inherited_controls.json"]
        data = json.loads(json_files[0].read_text())
        control_ids = {c["vuln_id"] for c in data["controls"]}
        assert data["resource"] == "aks.csp_inherited_controls"
        assert data["summary"]["total"] > 0
        assert "V-242382" not in control_ids
        assert "V-242381" in control_ids
        assert "V-242405" in control_ids

    def test_blank_cklb_uses_blank_target_comment(self, tmp_path):
        result = run_cli(
            "--blank",
            "-m", "aks",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 0
        cklb_files = list(tmp_path.glob("*.cklb"))
        assert [f.name for f in cklb_files] == ["aks_csp_inherited_controls.cklb"]
        data = json.loads(cklb_files[0].read_text())
        assert "CSP-inherited controls" in data["target_data"]["comments"]
        rules = data["stigs"][0]["rules"]
        statuses = {r["status"] for r in rules}
        rule_ids = {r["group_id"] for r in rules}
        assert statuses == {"not_a_finding"}
        assert "open" not in statuses
        assert "V-242382" not in rule_ids

    def test_blank_cklb_inherited_findings_include_quotes_and_links(self, tmp_path):
        result = run_cli(
            "--blank",
            "-m", "aks",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / "aks_csp_inherited_controls.cklb").read_text())

        for rule in data["stigs"][0]["rules"]:
            detail = rule["finding_details"]
            assert detail.startswith("Microsoft Learn evidence: "), (
                f"{rule['group_id']} finding details should identify Microsoft Learn evidence"
            )
            assert detail.count('"') >= 2, (
                f"{rule['group_id']} finding details should quote official documentation"
            )
            assert "https://learn.microsoft.com/en-us/azure/aks/" in detail, (
                f"{rule['group_id']} finding details should link to Azure documentation"
            )
            assert "Inherited CSP/baseline controls:" in detail

    def test_blank_without_module_uses_registered_csp_inherited_modules(self, tmp_path):
        result = run_cli(
            "--blank",
            "-o", "json",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 0
        assert sorted(f.name for f in tmp_path.glob("*.json")) == [
            "aks_csp_inherited_controls.json",
            "eks_csp_inherited_controls.json",
            "mysql_flexible_csp_inherited_controls.json",
            "postgres_flexible_csp_inherited_controls.json",
            "rds_postgres_csp_inherited_controls.json",
        ]

    def test_blank_mysql_json_writes_inherited_audit_log_storage_controls(self, tmp_path):
        result = run_cli(
            "--blank",
            "-m", "mysql_flexible",
            "-o", "json",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / "mysql_flexible_csp_inherited_controls.json").read_text())
        control_ids = {c["vuln_id"] for c in data["controls"]}
        assert data["resource"] == "mysql_flexible.csp_inherited_controls"
        assert control_ids == {"V-235099", "V-235100", "V-235101"}
        assert data["summary"]["not_met"] == 0
        for control in data["controls"]:
            assert "Azure Monitor diagnostic settings" in control["detail"]
            assert "Inherited CSP/baseline controls:" in control["detail"]

    def test_blank_postgres_json_writes_inherited_host_controls(self, tmp_path):
        result = run_cli(
            "--blank",
            "-m", "postgres_flexible",
            "-o", "json",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / "postgres_flexible_csp_inherited_controls.json").read_text())
        control_ids = {c["vuln_id"] for c in data["controls"]}
        assert data["resource"] == "postgres_flexible.csp_inherited_controls"
        assert len(control_ids) == 20
        assert "V-261875" in control_ids
        assert "V-261896" in control_ids
        assert data["summary"]["not_met"] == 0
        for control in data["controls"]:
            assert "Inherited CSP/baseline controls:" in control["detail"]

    def test_blank_rejects_resource_filter(self):
        result = run_cli("--blank", "-m", "aks", "-r", "*prod*")
        assert result.returncode == 2
        assert "--resource cannot be used with --blank" in result.stderr


class TestJsonOutput:
    def test_json_writes_per_resource_files(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json",
            "--output-dir", str(tmp_path),
        )
        assert result.returncode == 1
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 2
        for f in json_files:
            data = json.loads(f.read_text())
            assert "resource" in data
            assert "summary" in data
            assert "controls" in data

    def test_json_filenames_from_address(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json",
            "--output-dir", str(tmp_path),
            "-r", "*compliant_cluster",
        )
        assert result.returncode == 0 or result.returncode == 1
        filenames = {f.name for f in tmp_path.glob("*.json")}
        assert "azurerm_kubernetes_cluster_compliant_cluster.json" in filenames

    def test_json_stderr_shows_wrote(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json",
            "--output-dir", str(tmp_path),
        )
        assert "Wrote" in result.stderr

    def test_json_resource_filter(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json",
            "--output-dir", str(tmp_path),
            "-r", "*non_compliant*",
        )
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text())
        assert "non_compliant" in data["resource"]

    def test_output_filenames_are_sanitized_and_deduplicated(self, tmp_path):
        plan_path = tmp_path / "duplicate_names_plan.json"
        plan_path.write_text(json.dumps({
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": 'azurerm_kubernetes_cluster.example["prod/us"]',
                            "type": "azurerm_kubernetes_cluster",
                            "name": "example",
                            "values": {},
                        },
                        {
                            "address": 'azurerm_kubernetes_cluster.example["prod:us"]',
                            "type": "azurerm_kubernetes_cluster",
                            "name": "example",
                            "values": {},
                        },
                    ]
                }
            }
        }))

        run_cli(
            str(plan_path),
            "-o", "json", "cklb",
            "--output-dir", str(tmp_path),
        )

        assert sorted(f.name for f in tmp_path.glob("azurerm_kubernetes_cluster_example_prod_us*.json")) == [
            "azurerm_kubernetes_cluster_example_prod_us.json",
            "azurerm_kubernetes_cluster_example_prod_us_2.json",
        ]
        assert sorted(f.name for f in tmp_path.glob("azurerm_kubernetes_cluster_example_prod_us*.cklb")) == [
            "azurerm_kubernetes_cluster_example_prod_us.cklb",
            "azurerm_kubernetes_cluster_example_prod_us_2.cklb",
        ]

    def test_vuln_id_filter(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json",
            "--output-dir", str(tmp_path),
            "--vuln-id", "V-242381",
        )
        for f in tmp_path.glob("*.json"):
            data = json.loads(f.read_text())
            for ctrl in data["controls"]:
                assert ctrl["vuln_id"] == "V-242381"

    def test_severity_filter(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json",
            "--output-dir", str(tmp_path),
            "--severity", "CAT_I",
        )
        for f in tmp_path.glob("*.json"):
            data = json.loads(f.read_text())
            for ctrl in data["controls"]:
                assert ctrl["severity"] == "CAT I (High)"


class TestCklbOutput:
    @staticmethod
    def _assert_microsoft_learn_evidence(rule: dict, path_fragment: str = "/azure/") -> None:
        detail = rule["finding_details"]
        assert "Microsoft Learn evidence: " in detail, (
            f"{rule['group_id']} finding details should identify Microsoft Learn evidence"
        )
        assert detail.count('"') >= 2, (
            f"{rule['group_id']} finding details should quote official documentation"
        )
        assert f"https://learn.microsoft.com/en-us{path_fragment}" in detail, (
            f"{rule['group_id']} finding details should link to Azure documentation"
        )

    def test_cklb_writes_per_resource_files(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        assert len(cklb_files) == 2
        for f in cklb_files:
            data = json.loads(f.read_text())
            assert "target_data" in data
            assert "stigs" in data
            assert len(data["stigs"]) == 1
            assert len(data["stigs"][0]["rules"]) > 0

    def test_cklb_compliant_database_statuses(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "mysql_sample_plan.json"),
            "-m", "mysql_flexible",
            "-r", "azurerm_mysql_flexible_server.compliant",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        assert len(cklb_files) == 1
        data = json.loads(cklb_files[0].read_text())
        statuses = {r["status"] for r in data["stigs"][0]["rules"]}
        assert statuses <= {"not_a_finding", "not_applicable"}
        assert "open" not in statuses

    def test_cklb_manual_scope_controls_remain_open(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        data = json.loads(next(tmp_path.glob("*.cklb")).read_text())
        manual_rule = next(r for r in data["stigs"][0]["rules"] if r["group_id"] == "V-254800")
        assert manual_rule["status"] == "open"
        assert "manual review" in manual_rule["finding_details"]

    def test_cklb_compliant_findings_include_quotes_and_links(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        data = json.loads(next(tmp_path.glob("*.cklb")).read_text())

        for rule in data["stigs"][0]["rules"]:
            if rule["status"] in {"not_a_finding", "not_applicable"}:
                self._assert_microsoft_learn_evidence(rule, "/azure/aks/")

    def test_supported_template_cklb_not_findings_include_quotes_and_links(self, tmp_path):
        cases = [
            (
                "mysql_sample_plan.json",
                "mysql_flexible",
                "azurerm_mysql_flexible_server.compliant",
                "/azure/mysql/flexible-server/",
            ),
            (
                "postgres_sample_plan.json",
                "postgres_flexible",
                "azurerm_postgresql_flexible_server.compliant",
                "/azure/postgresql/",
            ),
        ]
        for fixture, module, resource, path_fragment in cases:
            output_dir = tmp_path / module
            output_dir.mkdir()
            run_cli(
                str(FIXTURES_DIR / fixture),
                "-m", module,
                "-r", resource,
                "-o", "cklb",
                "--recommendations",
                "--output-dir", str(output_dir),
            )
            data = json.loads(next(output_dir.glob("*.cklb")).read_text())

            for rule in data["stigs"][0]["rules"]:
                if rule["status"] in {"not_a_finding", "not_applicable"}:
                    if "requires manual review" in rule["finding_details"]:
                        assert "no Terraform property fully verifies" in rule["finding_details"]
                        continue
                    if "not applicable for unclassified" in rule["finding_details"]:
                        continue
                    self._assert_microsoft_learn_evidence(rule, path_fragment)
                    if "Inherited CSP/baseline controls:" in rule["finding_details"]:
                        continue
                    assert "Terraform properties addressed:" in rule["finding_details"]

    def test_cklb_open_findings(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.non_compliant_cluster",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        assert len(cklb_files) == 1
        data = json.loads(cklb_files[0].read_text())
        statuses = {r["status"] for r in data["stigs"][0]["rules"]}
        assert "open" in statuses

    def test_supported_template_cklb_open_findings_include_terraform_remediation(self, tmp_path):
        cases = [
            ("aks_sample_plan.json", "aks", "azurerm_kubernetes_cluster.non_compliant_cluster"),
            ("mysql_sample_plan.json", "mysql_flexible", "azurerm_mysql_flexible_server.non_compliant"),
            ("postgres_sample_plan.json", "postgres_flexible", "azurerm_postgresql_flexible_server.non_compliant"),
        ]
        for fixture, module, resource in cases:
            output_dir = tmp_path / f"{module}_open"
            output_dir.mkdir()
            run_cli(
                str(FIXTURES_DIR / fixture),
                "-m", module,
                "-r", resource,
                "-o", "cklb",
                "--recommendations",
                "--output-dir", str(output_dir),
            )
            data = json.loads(next(output_dir.glob("*.cklb")).read_text())
            open_rules = [rule for rule in data["stigs"][0]["rules"] if rule["status"] == "open"]
            assert open_rules

            remediated_open_rules = [
                rule
                for rule in open_rules
                if "Terraform remediation: configure" in rule["comments"]
            ]
            assert remediated_open_rules
            for rule in remediated_open_rules:
                comment = rule["comments"]
                assert "Recommended corrective action:" in comment
                assert "Terraform remediation: configure" in comment
                assert "https://registry.terraform.io/providers/hashicorp/azurerm/" in comment
                assert "azurerm_" in comment

    def test_cklb_host_name(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
            "--host-name", "my-server",
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        data = json.loads(cklb_files[0].read_text())
        assert data["target_data"]["host_name"] == "my-server"

    def test_cklb_stig_metadata(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        data = json.loads(cklb_files[0].read_text())
        stig = data["stigs"][0]
        assert "Kubernetes" in stig["stig_id"]
        assert stig["version"] == "2"

    def test_postgres_cklb_stig_metadata(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "postgres_sample_plan.json"),
            "-m", "postgres_flexible",
            "-r", "azurerm_postgresql_flexible_server.compliant",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        data = json.loads(cklb_files[0].read_text())
        stig = data["stigs"][0]
        assert stig["stig_id"] == "CD_Postgres_16_STIG"
        assert stig["version"] == "1"

    def test_cklb_stderr_message(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        assert "Wrote" in result.stderr

    def test_cklb_descriptions_use_stig_text(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        assert len(cklb_files) == 1
        data = json.loads(cklb_files[0].read_text())
        rules = {r["group_id"]: r for r in data["stigs"][0]["rules"]}
        assert "System kernel is responsible for memory, disk, and task management." in rules["V-242434"]["description"]
        assert "Automatically satisfied" not in rules["V-242434"]["description"]
        assert "Static Terraform-plan evaluation" not in rules["V-242434"]["check_content"]

    def test_cklb_rules_include_viewer_context(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--output-dir", str(tmp_path),
        )
        cklb_files = list(tmp_path.glob("*.cklb"))
        data = json.loads(cklb_files[0].read_text())
        stig = data["stigs"][0]
        rule = next(r for r in data["stigs"][0]["rules"] if r["group_id"] == "V-242434")
        assert data["id"]
        assert data["active"] is True
        assert data["mode"] == 1
        assert data["has_path"] is True
        assert data["cklb_version"] == "1.0"
        assert stig["uuid"]
        assert stig["display_name"] == "Kubernetes Security Technical Implementation Guide"
        assert stig["reference_identifier"] == "Kubernetes_STIG"
        assert stig["size"] == len(stig["rules"])
        assert rule["uuid"]
        assert rule["stig_uuid"] == stig["uuid"]
        assert rule["STIGUuid"] == stig["uuid"]
        assert rule["target_key"] == "azurerm_kubernetes_cluster.compliant_cluster"
        assert rule["stig_ref"] == "Kubernetes Security Technical Implementation Guide"
        assert rule["rule_version"] == "CNTR-K8-001620"
        assert rule["rule_ver"] == "CNTR-K8-001620"
        assert rule["rule_id"] == "SV-242434r961131_rule"
        assert rule["rule_id_src"] == "SV-242434r961131_rule"
        assert rule["group_title"] == "SRG-APP-000233-CTR-000585"
        assert rule["rule_title"] == "Kubernetes Kubelet must enable kernel protection."
        assert "System kernel is responsible for memory, disk, and task management." in rule["discussion"]
        assert 'ps -ef | grep kubelet' in rule["check_content"]
        assert "protectKernelDefaults" in rule["check_content"]
        assert "systemctl daemon-reload && systemctl restart kubelet" in rule["fix_text"]
        assert rule["documentable"] == "false"
        assert rule["check_content_ref"]["name"] == "M"
        assert rule["check_content_ref"]["href"] == "Kubernetes_STIG.xml"
        assert rule["group_tree"][0]["id"] == "V-242434"
        assert rule["ccis"] == ["CCI-001084"]
        assert rule["overrides"] == {}


class TestJunitOutput:
    def test_junit_flag_writes_consolidated_report(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "--junit",
            "--output-dir", str(tmp_path),
            "--no-color",
        )

        report_path = tmp_path / "junit.xml"
        root = ET.fromstring(report_path.read_text())
        cases = root.findall(".//testcase")
        failures = root.findall(".//failure")
        statuses = {
            prop.attrib["value"]
            for prop in root.findall(".//property[@name='status']")
        }

        assert result.returncode == 1
        assert report_path.is_file()
        assert root.attrib["name"] == "stig-check"
        assert int(root.attrib["tests"]) == len(cases)
        assert int(root.attrib["failures"]) == len(failures)
        assert failures
        assert "open" in statuses
        assert "not_a_finding" in statuses
        assert "Wrote" in result.stderr

    def test_junit_marks_compliant_database_controls_as_passing(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "mysql_sample_plan.json"),
            "-m", "mysql_flexible",
            "-r", "azurerm_mysql_flexible_server.compliant",
            "-o", "junit",
            "--output-dir", str(tmp_path),
        )

        root = ET.fromstring((tmp_path / "junit.xml").read_text())
        failures = root.findall(".//failure")
        statuses = {
            prop.attrib["value"]
            for prop in root.findall(".//property[@name='status']")
        }

        assert result.returncode == 0
        assert result.stdout == ""
        assert root.attrib["failures"] == "0"
        assert not failures
        assert statuses <= {"not_a_finding", "not_applicable"}

    def test_blank_junit_writes_csp_inherited_report(self, tmp_path):
        result = run_cli(
            "--blank",
            "-m", "aks",
            "--junit",
            "--output-dir", str(tmp_path),
        )

        root = ET.fromstring((tmp_path / "junit.xml").read_text())
        suite = root.find("testsuite")

        assert result.returncode == 0
        assert suite is not None
        assert suite.attrib["name"] == "AKS STIG Report: aks.csp_inherited_controls"
        assert root.attrib["failures"] == "0"
        statuses = {
            prop.attrib["value"]
            for prop in root.findall(".//property[@name='status']")
        }
        assert statuses == {"not_a_finding"}


class TestManualControls:
    def test_manual_controls_apply_to_cklb_status_and_comments(self, tmp_path):
        manual = tmp_path / "manual-controls.json"
        manual.write_text(json.dumps([
            {
                "Control ID": "V-242382",
                "Status": "Open",
                "Comments": "Reviewed manually and remains open.",
                "Details": "Manual evidence collected from runtime review.",
            },
        ]))

        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--manual-controls", str(manual),
            "--output-dir", str(tmp_path),
        )

        assert result.returncode == 1
        data = json.loads(next(tmp_path.glob("*.cklb")).read_text())
        rule = next(
            r for r in data["stigs"][0]["rules"] if r["group_id"] == "V-242382"
        )
        assert rule["status"] == "open"
        assert rule["finding_details"] == "Manual evidence collected from runtime review."
        assert rule["comments"] == "Reviewed manually and remains open."

    def test_recommendations_add_cklb_remediation_to_manual_comments(self, tmp_path):
        manual = tmp_path / "manual-controls.json"
        manual.write_text(json.dumps([
            {
                "Control ID": "V-242382",
                "Status": "Open",
                "Comments": "Reviewed manually and remains open.",
            },
        ]))

        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.compliant_cluster",
            "-o", "cklb",
            "--recommendations",
            "--manual-controls", str(manual),
            "--output-dir", str(tmp_path),
        )

        assert result.returncode == 1
        data = json.loads(next(tmp_path.glob("*.cklb")).read_text())
        rule = next(
            r for r in data["stigs"][0]["rules"] if r["group_id"] == "V-242382"
        )
        assert "Reviewed manually and remains open." in rule["comments"]
        assert "Recommended corrective action:" in rule["comments"]
        assert "azurerm_kubernetes_cluster" in rule["comments"]

    def test_manual_controls_apply_by_stig_id_to_json(self, tmp_path):
        manual = tmp_path / "manual-controls.json"
        manual.write_text(json.dumps({
            "controls": [
                {
                    "Control ID": "MYS8-00-000200",
                    "Status": "Not Applicable",
                    "Comments": "Runtime-only check is out of scope.",
                },
            ],
        }))

        result = run_cli(
            str(FIXTURES_DIR / "mysql_sample_plan.json"),
            "-m", "mysql_flexible",
            "-r", "azurerm_mysql_flexible_server.compliant",
            "-o", "json",
            "--manual-controls", str(manual),
            "--output-dir", str(tmp_path),
        )

        assert result.returncode == 0
        output_file = next(path for path in tmp_path.glob("*.json") if path.name != manual.name)
        data = json.loads(output_file.read_text())
        control = next(c for c in data["controls"] if c["vuln_id"] == "V-235096")
        assert control["status"] == "NOT_APPLICABLE"
        assert control["comments"] == "Runtime-only check is out of scope."

    def test_manual_controls_warn_for_bad_status_and_unmatched_id(self, tmp_path):
        manual = tmp_path / "manual-controls.json"
        manual.write_text(json.dumps([
            {"Control ID": "V-235096", "Status": "Closed", "Comments": "bad"},
            {"Control ID": "V-999999", "Status": "Open", "Comments": "missing"},
        ]))

        result = run_cli(
            str(FIXTURES_DIR / "mysql_sample_plan.json"),
            "-m", "mysql_flexible",
            "-r", "azurerm_mysql_flexible_server.compliant",
            "--manual-controls", str(manual),
            "--no-color",
        )

        assert result.returncode == 0
        assert "unsupported Status" in result.stderr
        assert "Control ID 'V-999999' did not match any evaluated control" in result.stderr


class TestMultipleOutputFormats:
    def test_text_and_json(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "text", "json",
            "--output-dir", str(tmp_path),
            "--no-color",
        )
        assert "AKS STIG Report" in result.stdout
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 2

    def test_text_and_cklb(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "text", "cklb",
            "--output-dir", str(tmp_path),
            "--no-color",
        )
        assert "AKS STIG Report" in result.stdout
        cklb_files = list(tmp_path.glob("*.cklb"))
        assert len(cklb_files) == 2

    def test_all_three_formats(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "text", "json", "cklb",
            "--output-dir", str(tmp_path),
            "--no-color",
        )
        assert "AKS STIG Report" in result.stdout
        assert len(list(tmp_path.glob("*.json"))) == 2
        assert len(list(tmp_path.glob("*.cklb"))) == 2

    def test_json_and_cklb_no_text(self, tmp_path):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json", "cklb",
            "--output-dir", str(tmp_path),
        )
        assert "AKS STIG Report" not in result.stdout
        assert len(list(tmp_path.glob("*.json"))) == 2
        assert len(list(tmp_path.glob("*.cklb"))) == 2


class TestOutputDir:
    def test_creates_output_dir_if_missing(self, tmp_path):
        new_dir = tmp_path / "nested" / "output"
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-o", "json",
            "--output-dir", str(new_dir),
        )
        assert new_dir.is_dir()
        assert len(list(new_dir.glob("*.json"))) == 2

    def test_module_filter(self, tmp_path):
        run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-o", "json",
            "--output-dir", str(tmp_path),
        )
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 2


class TestErrorHandling:
    def test_missing_file(self):
        result = run_cli("/nonexistent/path.json")
        assert result.returncode == 2
        assert "file not found" in result.stderr

    def test_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        result = run_cli(str(bad))
        assert result.returncode == 2
        assert "could not parse JSON" in result.stderr

    def test_no_args(self):
        result = run_cli()
        assert result.returncode != 0

    def test_unknown_module(self):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"), "-m", "nonexistent"
        )
        assert result.returncode == 2
        assert "unknown module" in result.stderr


class TestExitCodes:
    def test_all_met_returns_zero(self):
        result = run_cli(
            str(FIXTURES_DIR / "mysql_sample_plan.json"),
            "-r", "azurerm_mysql_flexible_server.compliant",
        )
        assert result.returncode == 0

    def test_findings_returns_one(self):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-r", "azurerm_kubernetes_cluster.non_compliant_cluster",
        )
        assert result.returncode == 1


class TestFailOnAndConfig:
    def test_fail_on_ignores_findings_below_threshold(self):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.non_compliant_cluster",
            "--vuln-id", "V-242443",
            "--fail-on", "CAT_I",
            "--no-color",
        )

        assert result.returncode == 0
        assert "NOT MET" in result.stdout

    def test_allowed_to_fail_exempts_matching_control(self):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.non_compliant_cluster",
            "--vuln-id", "V-242443",
            "--allowed-to-fail", "CNTR-K8-002720",
            "--no-color",
        )

        assert result.returncode == 0
        assert "NOT MET" in result.stdout

    def test_default_fail_on_preserves_existing_findings_exit_code(self):
        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "-m", "aks",
            "-r", "azurerm_kubernetes_cluster.non_compliant_cluster",
            "--vuln-id", "V-242443",
            "--no-color",
        )

        assert result.returncode == 1

    def test_auto_discovered_yaml_config_supplies_cli_defaults(self, tmp_path):
        reports_dir = tmp_path / "reports"
        (tmp_path / ".stig-check-config.yaml").write_text(
            "\n".join([
                "module: mysql_flexible",
                "resource: azurerm_mysql_flexible_server.compliant",
                "output: json",
                f"output-dir: {reports_dir}",
                "no-color: true",
            ]),
            encoding="utf-8",
        )

        result = run_cli(str(FIXTURES_DIR / "mysql_sample_plan.json"), cwd=tmp_path)

        assert result.returncode == 0
        assert result.stdout == ""
        assert sorted(f.name for f in reports_dir.glob("*.json")) == [
            "azurerm_mysql_flexible_server_compliant.json"
        ]

    def test_cli_fail_on_overrides_config_fail_on(self, tmp_path):
        config = tmp_path / ".stig-check-config.yml"
        config.write_text(
            "\n".join([
                "module: aks",
                "resource: azurerm_kubernetes_cluster.non_compliant_cluster",
                "vuln-id: V-242443",
                "fail-on: CAT I",
                "no-color: true",
            ]),
            encoding="utf-8",
        )

        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "--fail-on", "2",
            cwd=tmp_path,
        )

        assert result.returncode == 1

    def test_config_allowed_to_fail_exempts_matching_control(self, tmp_path):
        config = tmp_path / "stig.yml"
        config.write_text(
            "\n".join([
                "module: aks",
                "resource: azurerm_kubernetes_cluster.non_compliant_cluster",
                "vuln-id: V-242443",
                "allowed-to-fail:",
                "  - V-242443",
                "no-color: true",
            ]),
            encoding="utf-8",
        )

        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            "--config-file", str(config),
            cwd=tmp_path,
        )

        assert result.returncode == 0
        assert "NOT MET" in result.stdout

    def test_unknown_config_key_is_error(self, tmp_path):
        config = tmp_path / ".stig-check-config"
        config.write_text("unknown-option: true\n", encoding="utf-8")

        result = run_cli(
            str(FIXTURES_DIR / "aks_sample_plan.json"),
            cwd=tmp_path,
        )

        assert result.returncode == 2
        assert "unsupported config option" in result.stderr
