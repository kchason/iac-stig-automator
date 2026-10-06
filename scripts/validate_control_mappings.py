"""Validate control mapping JSON files against the committed JSON Schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "control_mapping.schema.json"
DEFAULT_MAPPING_GLOB = "src/stig_automator/modules/mappings/*_controls.json"


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _error_path(error: ValidationError) -> str:
    parts = [str(part) for part in error.absolute_path]
    return ".".join(parts) if parts else "<root>"


def _validate_file(path: Path, validator: Draft202012Validator) -> list[str]:
    try:
        document = _load_json(path)
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]

    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    return [
        f"{path}: {_error_path(error)}: {error.message}"
        for error in errors
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA,
        help="Path to the JSON Schema file.",
    )
    parser.add_argument(
        "mapping_files",
        nargs="*",
        type=Path,
        help="Mapping files to validate. Defaults to all module control mappings.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    schema = _load_json(args.schema)
    validator = Draft202012Validator(schema)
    validator.check_schema(schema)

    mapping_files = args.mapping_files or sorted(REPO_ROOT.glob(DEFAULT_MAPPING_GLOB))
    if not mapping_files:
        print("No control mapping files found.", file=sys.stderr)
        return 1

    errors: list[str] = []
    for path in mapping_files:
        errors.extend(_validate_file(path, validator))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    for path in mapping_files:
        print(f"Valid mapping: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
