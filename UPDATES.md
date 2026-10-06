# Updating STIG Checklist Metadata

This project evaluates Terraform plan JSON statically, but `.cklb` output needs the full DISA STIG rule context so STIG Viewer can render titles, descriptions, check text, fix text, CCIs, and source IDs.

## Offline runtime model

The CLI must never download STIG content at runtime. Download official DISA
content during development or build preparation, import it into committed JSON
catalogs, and ship those JSON files in the wheel.

## Retrieve STIG source content

1. Start from the official Cyber Exchange STIG downloads page: <https://www.cyber.mil/stigs/downloads/>.
2. Download the official DISA zip for the target release.
   - Kubernetes example: `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Kubernetes_V2R4_STIG.zip`
   - Crunchy Data Postgres 16 example: `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CD_Postgres_16_V1R2_STIG.zip`
   - Oracle MySQL 8.0 example: `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Oracle_MySQL_8-0_V2R2_STIG.zip`
3. Extract the `*_Manual-xccdf.xml` file from the zip.
4. Confirm the XCCDF benchmark metadata:
   - Benchmark ID, such as `Kubernetes_STIG`
   - `<version>`
   - `<plain-text id="release-info">`

## Import metadata into raw JSON

Store raw checklist metadata under `src/stig_automator/modules/stigs/`.

Use the checked-in importer for raw module control JSONs. Terraform callback
mappings live separately under `src/stig_automator/modules/mappings/`.

```bash
python scripts/import_stig_controls.py \
  --stig-zip /path/to/U_CD_Postgres_16_V1R2_STIG.zip \
  --controls-json src/stig_automator/modules/stigs/postgres_flexible_controls.json \
  --manifest-json src/stig_automator/modules/stigs/postgres_manifest.json \
  --source-url https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CD_Postgres_16_V1R2_STIG.zip

python scripts/import_stig_controls.py --full-catalog \
  --stig-zip /path/to/U_CD_Postgres_16_V1R2_STIG.zip \
  --controls-json src/stig_automator/modules/stigs/postgres_flexible_controls.json \
  --manifest-json src/stig_automator/modules/stigs/postgres_manifest.json \
  --source-url https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CD_Postgres_16_V1R2_STIG.zip
```

Run the same importer against provider-specific catalogs that share a STIG, such
as both `postgres_flexible_controls.json` and `rds_postgres_controls.json`. Without
`--full-catalog`, the importer matches existing entries by `vuln_id`, replaces
STIG-facing fields with official XCCDF content, preserves the existing `check`
key, and fails if a current control is not present in the official archive. With
`--full-catalog`, it writes every XCCDF Group in archive order so the committed
catalog matches the official control count.

Current AKS/Kubernetes metadata lives at:

```text
src/stig_automator/modules/stigs/kubernetes_metadata.json
```

Each vulnerability entry should include, at minimum:

```json
{
  "V-242434": {
    "rule_id": "SV-242434r961131_rule",
    "group_title": "SRG-APP-000233-CTR-000585",
    "cci": ["CCI-001084"],
    "title": "Kubernetes Kubelet must enable kernel protection.",
    "description": "Official VulnDiscussion text",
    "check_content": "Official Check Text",
    "fix_text": "Official Fix Text",
    "documentable": "false",
    "check_content_ref": {
      "href": "Kubernetes_STIG.xml",
      "name": "M"
    }
  }
}
```

Preserve multiline text exactly from the XCCDF. Use JSON arrays for `cci`, not comma-separated strings. Commit the generated import manifest so reviewers can verify the source archive, SHA256 checksum, benchmark ID, version, release info, and official control count.

Current imported database manifests live at:

```text
src/stig_automator/modules/stigs/postgres_manifest.json
src/stig_automator/modules/stigs/mysql_manifest.json
```

## Update module metadata

When the STIG release changes, update the module class metadata to match the XCCDF:

```python
stig_benchmark_id = "Kubernetes_STIG"
stig_version = "2"
stig_release_info = "Release: 4 Benchmark Date: 02 Jul 2025"
```

If controls are added, removed, or renumbered:

1. Update the module control catalog JSON under `src/stig_automator/modules/stigs/`, such as `kubernetes_catalog.json`, `mysql_flexible_controls.json`, or `postgres_flexible_controls.json`.
2. Update automation mapping JSON under `src/stig_automator/modules/mappings/`, such as `aks_controls.json`, when direct Terraform checks, managed defaults, manual-scope controls, or not-applicable controls change.
3. Update evidence JSON under `src/stig_automator/modules/mappings/`, such as `aks_evidence.json`, `mysql_flexible_evidence.json`, or `postgres_flexible_evidence.json`, when checklist comments, official links, or direct documentation quotes change.
4. Update tests for control counts, new or removed IDs, and representative CKLB fields.

Do not assume an existing Terraform check still maps to the same `vuln_id` after
a STIG release update. Review official titles, check text, and fix text for each
imported control and remap automation checks when DISA renumbers or changes
requirements.

## Package data

Raw metadata JSON must be included in built wheels. Keep this package-data entry in `pyproject.toml`:

```toml
[tool.setuptools.package-data]
"stig_automator.modules" = ["stigs/*.json", "mappings/*.json"]
```

After a build/install, verify the metadata can be read through `importlib.resources`.

## Development hooks

Install and run pre-commit hooks before submitting checklist updates:

```bash
pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
```

Update hook versions periodically, especially when refreshing STIG content:

```bash
pre-commit autoupdate
pre-commit run --all-files
```

Review `.pre-commit-config.yaml` changes before committing hook updates. Do not mix unrelated hook upgrades with checklist metadata changes unless the update is intentional.

## Required verification

Run focused tests first, then the full quality suite:

```bash
pytest tests/modules/test_aks.py tests/test_cli.py::TestCklbOutput --tb=short -q
pytest --tb=short -q
autoflake --check --remove-all-unused-imports --remove-unused-variables -r src/ tests/
flake8 src/ tests/
python -m build
pip install --user --force-reinstall dist/*.whl
stig-check --list-modules
```

For CKLB changes, also generate a checklist from a fixture and inspect a known rule:

```bash
stig-check tests/fixtures/aks_sample_plan.json -m aks -r azurerm_kubernetes_cluster.compliant_cluster -o cklb --output-dir /tmp/stig-check
```

Confirm the generated `.cklb` includes the official `group_id`, `rule_id`, `rule_version`, `group_title`, `rule_title`, `discussion`, `check_content`, `fix_text`, `check_content_ref`, and `ccis`.
