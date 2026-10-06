# STIG Automator

Evaluate Terraform plan and state JSON files against DISA STIG controls for Azure and AWS resources.

STIG Automator auto-detects resources in your Terraform plan, runs the applicable STIG checks, and reports which controls are met or not met — all from static analysis, with no cloud API calls required.

**Triage tool only.** STIG Automator helps prioritize review of Terraform plans. It does not guarantee compliance, completeness, or correctness. Every control result must be validated by a human before it is used for authorization, accreditation, or audit evidence.

## Features

- **Auto-detection** — scans your Terraform plan for known resource types and runs the matching STIG modules automatically
- **Modular architecture** — each STIG is a self-contained module; adding new STIGs requires no changes to the core
- **Flexible filtering** — filter by module, Terraform resource address (glob patterns), vulnerability ID, STIG ID, or severity level
- **Multiple output formats** — text (with color), JSON, JUnit XML, or multiple formats at once
- **STIG Viewer export** — generate `.cklb` checklist files compatible with DISA STIG Viewer 3.x
- **CI test report export** — generate JUnit XML for GitLab and GitHub test report UIs
- **Manual control overlays** — apply reviewer-supplied statuses and comments after automated checks
- **Failure gating** — fail only on selected severity thresholds while exempting justified controls
- **Config files** — load CLI defaults from `.stig-check-config`, `.stig-check-config.yaml`, or `.stig-check-config.yml`
- **Blank CSP-inherited output** — generate no-plan checklists containing only controls inherited from the cloud provider
- **Zero runtime dependencies** — stdlib only

## Available Modules

| Module | STIG | Terraform Resource Type | Controls |
|---|---|---|---|
| `aks` | DISA STIG for Kubernetes, V2 | `azurerm_kubernetes_cluster` | 94 |
| `azure_sql_database` | Microsoft Azure SQL Database STIG, V2R2 | `azurerm_mssql_server` | 76 |
| `azure_sql_managed_instance` | Microsoft Azure SQL Managed Instance STIG, V1R1 | `azurerm_mssql_managed_instance` | 84 |
| `eks` | DISA STIG for Kubernetes, V2 | `aws_eks_cluster` | 94 |
| `mysql_flexible` | DISA STIG for MySQL 8.0 | `azurerm_mysql_flexible_server` | 17 |
| `postgres_flexible` | Crunchy Data Postgres 16 STIG, V1R2 | `azurerm_postgresql_flexible_server` | 111 |
| `rds_mysql` | DISA STIG for MySQL 8.0 | `aws_db_instance` / `aws_rds_cluster` (`engine` = MySQL) | 17 |
| `rds_postgres` | Crunchy Data Postgres 16 STIG, V1R2 | `aws_db_instance` / `aws_rds_cluster` (`engine` = PostgreSQL) | 111 |

### Database provider value notes

Database modules use the parameter names and enum values documented by each CSP. For example, Azure MySQL Flexible Server `audit_log_events` expects Azure event classes such as `CONNECTION`, `CONNECTION_V2`, `DCL`, `DDL`, and `GENERAL`, while Amazon RDS for MySQL `server_audit_events` uses MariaDB Audit Plugin values such as `CONNECT`, `QUERY`, `QUERY_DCL`, and `QUERY_DDL`. Check results include CSP documentation, Terraform provider documentation, and upstream RDBMS references where the provider setting maps to MySQL, MariaDB, PostgreSQL, or pgAudit behavior.

## Installation

```bash
pip install iac-stig-automator
```

From a checkout of this repository:

```bash
pip install .

# For development (editable install with test dependencies)
pip install -e ".[dev]"
```

This installs the `stig-check` command.

## Usage

### Generate a Terraform plan JSON

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

### Auto-detect and evaluate all resources

```bash
stig-check plan.json
```

### Specify a module

```bash
stig-check plan.json -m aks
stig-check plan.json -m eks
stig-check plan.json -m mysql_flexible
stig-check plan.json -m postgres_flexible
stig-check plan.json -m rds_mysql
stig-check plan.json -m rds_postgres
stig-check plan.json -m azure_sql_database
stig-check plan.json -m azure_sql_managed_instance
```

### Filter by Terraform resource address

```bash
# Glob patterns supported
stig-check plan.json -r "module.prod.*"
stig-check plan.json -r "azurerm_kubernetes_cluster.my_cluster"
```

### Filter by vulnerability or STIG ID

```bash
stig-check plan.json --vuln-id V-242381
stig-check plan.json --stig-id CNTR-K8-000370
```

### Filter by minimum severity

```bash
# CAT_I only (high)
stig-check plan.json --severity CAT_I

# CAT_I + CAT_II (high + medium)
stig-check plan.json --severity CAT_II
```

### Failure gating and config files

By default, `stig-check` exits with code `1` for any non-exempt unmet control, which is equivalent to `--fail-on CAT_III`. Use `--fail-on` to gate only on CAT I, CAT II-or-higher, or CAT III-or-higher findings. Accepted values include `CAT_I`, `CAT_II`, `CAT_III`, `CAT I`, `CAT II`, `CAT III`, `1`, `2`, and `3`.

```bash
# Report all evaluated controls, but exit 1 only for CAT I findings
stig-check plan.json --fail-on CAT_I

# Exempt a justified control from failure gating
stig-check plan.json --allowed-to-fail V-242382
```

Configuration is loaded from the first file found in the current directory: `.stig-check-config`, `.stig-check-config.yaml`, or `.stig-check-config.yml`. Use `--config-file path/to/file.yml` to choose a different file. CLI arguments override config file values.

```yaml
module: aks
resource:
  - azurerm_kubernetes_cluster.prod
output: [text, cklb]
output-dir: ./results
fail-on: CAT_II
allowed-to-fail:
  - V-242382
  - CNTR-K8-000270
no-color: true
```

Config keys mirror CLI option names without leading dashes. Repeatable CLI options may be written as a single string or a list.

### Output formats

Multiple formats can be specified at once. `text` prints to stdout; `json` and `cklb` write one file per resource to `--output-dir`; `junit` writes a single `junit.xml` file.

```bash
stig-check plan.json                        # default: text to stdout
stig-check plan.json -o json                # one .json per resource
stig-check plan.json -o cklb                # one .cklb per resource (STIG Viewer 3.x)
stig-check plan.json -o junit               # one junit.xml for CI test reports
stig-check plan.json --junit                # also write junit.xml with the selected formats
stig-check plan.json -o text json cklb      # text, JSON, and CKLB at once
stig-check plan.json -o json --output-dir ./results   # write to a specific directory
stig-check plan.json --no-color             # text without ANSI codes
stig-check plan.json --recommendations      # include Terraform remediation guidance
```

The `json` output writes a structured report per resource with summary and per-control details.

The `cklb` output writes a JSON file per resource compatible with DISA STIG Viewer 3.x. Each control is mapped to a rule with status `not_a_finding`, `open`, or `not_applicable`, plus viewer context fields such as group ID, rule ID, STIG ID, discussion, check content, and fix text. Use `--recommendations` to include recommended corrective action and Terraform resource properties/keys in text output and CKLB comments for open findings.

The `junit` output writes one JUnit XML file named `junit.xml`. Each evaluated control is a testcase: `not_a_finding` and `not_applicable` controls pass, while `open` controls fail.

```bash
# Specify a hostname for the cklb checklist target
stig-check plan.json -o cklb --host-name prod-aks-cluster
```

### Manual control overlays

Use `--manual-controls` to apply reviewer-supplied statuses and comments after automated checks. The file can be a JSON list, or an object with a `controls` list. Each entry must include `Control ID`, `Status`, and `Comments`; `Details` is optional and fills checklist Finding Details when populated. `Control ID` may match either the vulnerability ID or STIG ID, and `Status` must be `Not a Finding`, `Open`, or `Not Applicable`.

```json
[
  {
    "Control ID": "V-242381",
    "Status": "Not a Finding",
    "Comments": "Reviewed workload evidence manually.",
    "Details": "Manual evidence confirms the setting is enforced at runtime."
  }
]
```

```bash
stig-check plan.json -o cklb --manual-controls manual-controls.json
```

Invalid statuses and unmatched control IDs are skipped with warnings on stderr.

AKS checklist context is stored as raw JSON in `src/stig_automator/modules/stigs/kubernetes_metadata.json`. When DISA publishes a new Kubernetes STIG, update that JSON export from the XCCDF source so generated `.cklb` files include current titles, discussions, check text, fix text, CCIs, and source rule IDs.

### Blank CSP-inherited output

Use `--blank` to generate output without a Terraform plan file. Blank output includes only controls marked as inherited from the cloud service provider, so resource filters are not supported. If `-m` is omitted, all modules with CSP-inherited controls are used.

```bash
stig-check --blank -m aks
stig-check --blank -m aks -o cklb --output-dir ./results
```

### Verbose mode

```bash
# Show descriptions for all controls, not just failing ones
stig-check plan.json -v
```

### List available modules

```bash
stig-check --list-modules
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | All evaluated controls are met |
| 1 | One or more non-exempt controls match the active failure threshold |
| 2 | Usage error, file not found, or JSON parse error |

## Adding a New STIG Module

Add raw STIG controls under `src/stig_automator/modules/stigs/` and editable behavior and evidence mappings under `src/stig_automator/modules/mappings/`. Implement Terraform validation callbacks in a module file under `src/stig_automator/modules/`, subclass `BaseStigModule`, and decorate the class with `@register`.

Use `automatic_platform_text` for inherited or platform controls and `validation_function_name` for Terraform evaluation callbacks. No central registry file needs editing; modules are auto-imported.

See [CONTRIBUTING.md](https://github.com/kchason/iac-stig-automator/blob/main/CONTRIBUTING.md) and [docs/mapping_schema.md](https://github.com/kchason/iac-stig-automator/blob/main/docs/mapping_schema.md) for the field schema, import workflow, and test expectations.

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

## Project Structure

```
src/stig_automator/
├── cli.py              # CLI entry point (stig-check command)
├── models.py           # Severity, StigControl, CheckResult
├── plan_parser.py      # Terraform plan JSON parsing
├── output.py           # Text, JSON, JUnit, and cklb output renderers
├── util.py             # Safe nested dict/list navigation helpers
├── registry.py         # Module registry and auto-detection
└── modules/
    ├── _base.py            # BaseStigModule abstract base class
    ├── aks.py              # AKS Kubernetes STIG (94 controls)
    ├── azure_sql_database.py # Azure SQL Database STIG (76 controls)
    ├── azure_sql_managed_instance.py # Azure SQL Managed Instance STIG (84 controls)
    ├── mappings/           # Editable behavior/evidence mappings
    ├── stigs/              # Raw STIG metadata exports used by cklb output
    ├── eks.py              # Amazon EKS Kubernetes STIG (94 controls)
    ├── mysql_flexible.py   # MySQL Flexible Server STIG (17 controls)
    ├── postgres_flexible.py # Azure PostgreSQL Flexible Server STIG (111 controls)
    ├── rds_mysql.py        # Amazon RDS MySQL STIG (17 controls)
    └── rds_postgres.py     # Amazon RDS PostgreSQL STIG (111 controls)
```

## License

STIG Automator is released under the [MIT License](https://github.com/kchason/iac-stig-automator/blob/main/LICENSE). Read [NOTICE](https://github.com/kchason/iac-stig-automator/blob/main/NOTICE), [DISCLAIMER](https://github.com/kchason/iac-stig-automator/blob/main/DISCLAIMER.md), [SECURITY](https://github.com/kchason/iac-stig-automator/blob/main/SECURITY.md), [CONTRIBUTING](https://github.com/kchason/iac-stig-automator/blob/main/CONTRIBUTING.md), and the [changelog](https://github.com/kchason/iac-stig-automator/blob/main/CHANGELOG.md) before relying on a result.
