# Contributing

Thanks for helping improve STIG Automator. The project is intentionally static and offline: checks evaluate Terraform plan/state JSON and must not call cloud provider APIs.

## Scope

STIG Automator is a triage tool. It does not guarantee compliance, completeness, or correctness. Automated results must be validated by a human before they are used for authorization, accreditation, or audit evidence.

## License

By contributing, you agree that your contributions are licensed under the MIT License in `LICENSE` and that the software is provided "as is", without warranty, as stated in `LICENSE` and `DISCLAIMER.md`.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make the change and add or update tests.
3. Run the quality checks below.
4. Open a pull request that explains the behavior change and how you tested it.

Do not commit classified material, controlled unclassified information (CUI), real Terraform plans, state files, credentials, subscription IDs, tenant IDs, or account identifiers. Fixtures in `tests/fixtures/` must use synthetic values.

## Development setup

Use Python 3.10 or newer.

```bash
python3 -m pip install -e ".[dev]"
stig-check --list-modules
```

## Formatting and quality checks

Run focused tests for your change first, then run the full suite.

```bash
pytest --tb=short -q
python3 scripts/validate_control_mappings.py
autoflake --check --remove-all-unused-imports --remove-unused-variables -r src/ tests/
flake8 src/ tests/
python3 -m build
python3 -m pip install dist/*.whl
PATH="$HOME/.local/bin:$PATH" stig-check --list-modules
```

Keep edits ASCII unless the file already uses non-ASCII text from official STIG content. Keep generated schemas stable unless tests and docs are updated together.

## Security scans

CI runs TruffleHog, Checkov, and Trivy on pull requests and pushes to `main`. Run the same checks locally with Docker:

```bash
bash scripts/security-scan.sh
```

Reports are written to `security-reports/`, which is gitignored. Regenerate them with `bash scripts/security-scan.sh` after changing the Dockerfile or CI scan settings. TruffleHog fails on verified secrets. Checkov scans the Dockerfile and GitHub Actions workflows, and skips `tests/` plus `CKV_GHA_8` (major-version action tags). Trivy 0.75 scans the container image and writes `sbom.cdx.json` and `sbom.spdx.json` with vulnerabilities included. CycloneDX stores them in the `vulnerabilities` array. SPDX stores them as `SECURITY` advisory `externalRefs`. The local script also fails when Trivy finds a fixed HIGH or CRITICAL vulnerability, matching CI.

## Repository layout

- `src/stig_automator/modules/stigs/`: raw imported STIG catalog, metadata, controls, and source manifests.
- `src/stig_automator/modules/mappings/`: local control behavior and evidence mappings.
- `src/stig_automator/modules/*.py`: Terraform plan validation callbacks and module registration.
- `tests/fixtures/`: committed Terraform plan JSON fixtures.
- `tests/modules/`: module-specific behavior coverage.

## Updating checklist/STIG content

1. Download the official DISA STIG ZIP.
2. Run the importer against the raw controls JSON:

```bash
python scripts/import_stig_controls.py \
  --stig-zip /path/to/U_CD_Postgres_16_V1R2_STIG.zip \
  --controls-json src/stig_automator/modules/stigs/postgres_flexible_controls.json \
  --manifest-json src/stig_automator/modules/stigs/postgres_manifest.json \
  --source-url https://example.invalid/source.zip

python scripts/import_stig_controls.py --full-catalog \
  --stig-zip /path/to/U_CD_Postgres_16_V1R2_STIG.zip \
  --controls-json src/stig_automator/modules/stigs/postgres_flexible_controls.json \
  --manifest-json src/stig_automator/modules/stigs/postgres_manifest.json \
  --source-url https://example.invalid/source.zip
```

Use `--full-catalog` to replace the module catalog with every XCCDF Group from the archive. The default importer still updates existing `vuln_id` entries only.

3. Review renumbered or removed controls against the matching mapping file in `src/stig_automator/modules/mappings/`.
4. Update module benchmark metadata (`stig_version`, `stig_release_info`, benchmark title/id) when the XCCDF changes.
5. Run module tests and inspect generated `.cklb` output for representative controls.

Raw STIG files should not contain local callback fields such as `check`.

## Editing controls, inherited text, and validation callbacks

Use `docs/mapping_schema.md` as the human-readable source of truth for mapping fields and `schemas/control_mapping.schema.json` as the machine-readable schema enforced by CI.

To edit inherited or automatic platform text:

1. Open the module control mapping, for example `src/stig_automator/modules/mappings/aks_controls.json`.
2. Find the control ID.
3. Edit `automatic_platform_text`, `evidence_key`, `cklb_status`, or `include_in_blank_cklb`.
4. Run:

```bash
python3 scripts/validate_control_mappings.py
pytest --tb=short -q tests/modules/test_aks.py tests/test_cli.py
```

To point a control at a validation callback:

1. Implement or update a `_check_*` function in the module Python file.
2. Register it in the module's `CONTROL_CHECKS` dictionary.
3. Set the mapping entry's `validation_function_name` to that registry key.
4. Set `remediation_key` when open findings should include Terraform remediation guidance.
5. Run `python3 scripts/validate_control_mappings.py`.
6. Add or update a fixture-driven test that proves the callback returns both met and open results when practical.

## Blank CKLB behavior

`stig-check --blank` includes controls whose mapping sets `include_in_blank_cklb` to `true`. The generated CKLB status comes from `cklb_status`, and finding details come from `automatic_platform_text` plus mapped evidence.

Use blank CKLB for inherited or managed platform controls, not Terraform validation controls.

## Adding a new module

1. Add raw STIG controls under `src/stig_automator/modules/stigs/`.
2. Add behavior mappings under `src/stig_automator/modules/mappings/`.
3. Add evidence mappings under `src/stig_automator/modules/mappings/` when result text should cite provider documentation.
4. Create `src/stig_automator/modules/<module_name>.py`.
5. Subclass `BaseStigModule` and decorate the class with `@register`.
6. Implement `controls()` and, if needed, `find_resources()`.
7. Use `load_control_mappings()` from `src/stig_automator/modules/_mapping.py` so mapping validation is consistent.
8. Add tests under `tests/modules/` and fixtures under `tests/fixtures/`.
9. Update README examples and module lists when the new module is user-facing.

No central registry file needs editing; modules are auto-imported from `src/stig_automator/modules/`.

## Publishing the repository

Publish this tree as one commit on an empty GitHub repository. Do not push the existing local history.

1. Create an empty public repository at `github.com/kchason/iac-stig-automator` with no README, license, or `.gitignore`.
2. From a clean checkout of this tree, commit the files once and push that commit to `main`.

After the repository exists, turn on these GitHub settings before accepting pull requests:

- Dependency graph, Dependabot alerts, and Dependabot security updates.
- Secret scanning and push protection.
- Private vulnerability reporting.
- Code scanning. The CodeQL workflow fills the Security tab.
- A ruleset on `main`: pull request required, one approving review, code owner review, stale reviews dismissed, force-push blocked, and these required checks: Lint, Validate JSON schemas, Test (Python 3.10), Test (Python 3.11), Test (Python 3.12), Test (Python 3.13), Build, TruffleHog, Checkov, Trivy, CodeQL, and Dependency Review.

## Publishing to PyPI

A personal PyPI account can own `iac-stig-automator`. A PyPI organization is optional. The project name is global, so the install command stays `pip install iac-stig-automator` either way.

Do not store a PyPI token in the repository. The release workflow uses GitHub trusted publishing.

1. Sign in to PyPI as the account that should own the project.
2. Create a GitHub environment named `pypi` on this repository.
3. Add a trusted publisher for project `iac-stig-automator`: owner `kchason`, repository `iac-stig-automator`, workflow `publish.yml`, environment `pypi`. If the project does not exist yet, add that publisher as a pending publisher. The first successful release creates the project under the account that added the publisher.
4. Confirm `main` contains the version in `pyproject.toml`.
5. Create a GitHub release whose tag matches that version, prefixed with `v`, such as `v0.3.0`. The publish workflow builds the distributions and uploads them. A tag that does not match `pyproject.toml` fails before upload.
