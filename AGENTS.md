# Agent Instructions

## Project Overview

STIG Automator is a Python CLI package that evaluates Terraform plan JSON against DISA STIG controls. The package installs the `stig-check` command and performs static analysis only; do not add cloud API calls for checks unless the product direction changes.

## Repository Structure

- `src/stig_automator/cli.py` - CLI argument parsing and command entry point.
- `src/stig_automator/models.py` - shared `Severity`, `StigControl`, and `CheckResult` data models.
- `src/stig_automator/plan_parser.py` - Terraform plan JSON parsing and resource filtering.
- `src/stig_automator/output.py` - text, JSON, and STIG Viewer `.cklb` output renderers.
- `src/stig_automator/registry.py` - STIG module registration, lookup, and auto-detection.
- `src/stig_automator/util.py` - safe nested dictionary/list navigation helpers.
- `src/stig_automator/modules/` - one module per supported STIG/resource type.
- `tests/` - pytest coverage and Terraform plan fixtures for CLI, parser, output, registry, and modules.

## Setup

- Use Python 3.10 or newer.
- Install the project for development with `pip install -e ".[dev]"`.
- The project is designed to have no runtime dependencies beyond the Python standard library.

## Development Guidelines

- Keep STIG checks static and deterministic from Terraform plan/state JSON.
- Prefer small helper functions for individual controls; each check should return `(met: bool, detail: str)`.
- Register new STIG modules with the `@register` decorator and subclass `BaseStigModule`.
- Add new modules under `src/stig_automator/modules/` and matching tests under `tests/modules/`.
- Reuse helpers from `util.py` for nested resource reads instead of open-coded dictionary traversal.
- Keep CLI behavior and exit codes compatible with the README unless intentionally changing the public interface.
- Preserve generated output schemas for JSON and `.cklb` unless tests and documentation are updated together.

## Testing and Quality Checks

Run the focused tests for your change first, then run the full suite before submitting.

- `pytest --tb=short -q`
- `autoflake --check --remove-all-unused-imports --remove-unused-variables -r src/ tests/`
- `flake8 src/ tests/`

CI also builds the package and verifies the installed CLI:

- `python -m build`
- `pip install dist/*.whl`
- `stig-check --list-modules`

## Documentation

- Update `README.md` when changing installation, CLI flags, output formats, exit codes, or adding a supported STIG module.
- Keep examples aligned with the current module registry and public command names.

## Quick Reference

| Task | Command |
|---|---|
| Install (dev) | `pip install -e ".[dev]"` |
| Run tests | `pytest --tb=short -q` |
| Lint (autoflake) | `autoflake --check --remove-all-unused-imports --remove-unused-variables -r src/ tests/` |
| Lint (flake8) | `flake8 src/ tests/` |
| Run CLI | `stig-check <plan.json>` |
| List modules | `stig-check --list-modules` |

## Non-Obvious Notes

- The `stig-check` entry point is installed to `~/.local/bin/`. Ensure `PATH` includes `$HOME/.local/bin` if invoking from shell.
- Exit code 1 from `stig-check` means "one or more controls are not met" — this is expected behavior when running against non-compliant test fixtures, not a failure.
- Test fixtures live in `tests/fixtures/` (committed JSON files). No Terraform binary or cloud access is needed to run tests.
- CI tests across Python 3.10–3.13 (four versions).
