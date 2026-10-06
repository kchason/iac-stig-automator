import json
from importlib import resources
from pathlib import Path

from jsonschema import Draft202012Validator
import stig_automator.modules as stig_modules
from stig_automator.modules._mapping import load_control_mappings
from stig_automator.registry import get_module


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_MAPPING_SCHEMA = REPO_ROOT / "schemas" / "control_mapping.schema.json"


CONTROL_MAPPING_FILES = {
    "aks": "mappings/aks_controls.json",
    "azure_sql_database": "mappings/azure_sql_database_controls.json",
    "azure_sql_managed_instance": "mappings/azure_sql_managed_instance_controls.json",
    "eks": "mappings/eks_controls.json",
    "mysql_flexible": "mappings/mysql_flexible_controls.json",
    "postgres_flexible": "mappings/postgres_flexible_controls.json",
    "rds_mysql": "mappings/rds_mysql_controls.json",
    "rds_postgres": "mappings/rds_postgres_controls.json",
}
RAW_CONTROL_FILES = [
    "stigs/azure_sql_database_controls.json",
    "stigs/azure_sql_managed_instance_controls.json",
    "stigs/mysql_flexible_controls.json",
    "stigs/postgres_flexible_controls.json",
    "stigs/rds_mysql_controls.json",
    "stigs/rds_postgres_controls.json",
]


def _load_json(path: str):
    with resources.files(stig_modules).joinpath(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def test_control_mappings_match_json_schema():
    schema = json.loads(CONTROL_MAPPING_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.check_schema(schema)
    for path in CONTROL_MAPPING_FILES.values():
        document = _load_json(path)
        errors = sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
        assert errors == [], f"{path}: {[error.message for error in errors]}"


def test_raw_stig_controls_do_not_define_local_callbacks():
    for path in RAW_CONTROL_FILES:
        controls = _load_json(path)
        assert all("check" not in control for control in controls), path


def test_control_mappings_use_public_behavior_schema():
    for module_name, path in CONTROL_MAPPING_FILES.items():
        data = _load_json(path)
        entries = list(data["controls"].values())
        if "default" in data:
            entries.append(data["default"])

        for mapping in entries:
            assert bool(mapping.get("automatic_platform_text")) != bool(
                mapping.get("validation_function_name"),
            ), f"{module_name} mapping must define exactly one behavior path"
            assert "check" not in mapping
            assert "status" not in mapping


def test_control_mapping_loader_rejects_unknown_validation_function():
    data = {
        "controls": {
            "V-1": {
                "validation_function_name": "missing_callback",
            },
        },
    }

    try:
        load_control_mappings(data, module_name="test", validation_functions={})
    except ValueError as exc:
        assert "unknown validation_function_name" in str(exc)
    else:
        raise AssertionError("unknown validation_function_name should fail validation")


def test_blank_cklb_inclusion_is_driven_by_mapping_flags():
    for module_name in ("aks", "eks"):
        module = get_module(module_name)
        data = _load_json(CONTROL_MAPPING_FILES[module_name])
        expected = {
            control_id
            for control_id, mapping in data["controls"].items()
            if mapping.get("include_in_blank_cklb")
        }
        if data["default"].get("include_in_blank_cklb"):
            explicit_ids = set(data["controls"])
            expected.update(
                control.vuln_id
                for control in module.controls()
                if control.vuln_id not in explicit_ids
            )

        actual = {
            control.vuln_id
            for control in module.controls()
            if control.csp_inherited
        }

        assert actual == expected
