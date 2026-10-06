# CI Integration Examples

Use `stig-check` in CI to evaluate Terraform plan JSON before infrastructure is
applied. The examples below build a Terraform plan, convert it to JSON, and use
`--fail-on` to decide which finding severities should block the pipeline.

By default, `stig-check` exits with code `1` for any non-exempt unmet control,
equivalent to `--fail-on CAT_III`. Raise the threshold to allow lower-severity
findings while still reporting them.

## GitLab CI

```yaml
stages:
  - validate

stig_check:
  stage: validate
  image: python:3.12
  before_script:
    - apt-get update && apt-get install -y unzip curl
    - curl -fsSL https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip -o terraform.zip
    - unzip terraform.zip -d /usr/local/bin
    - pip install stig-automator
  script:
    - terraform init -backend=false
    - terraform plan -out=tfplan
    - terraform show -json tfplan > plan.json
    - stig-check plan.json --fail-on CAT_II
  artifacts:
    when: always
    paths:
      - plan.json
```

To keep reports as artifacts, publish JUnit results in the GitLab UI, and block
only CAT I findings:

```yaml
stig_check_report:
  stage: validate
  image: python:3.12
  before_script:
    - apt-get update && apt-get install -y unzip curl
    - curl -fsSL https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip -o terraform.zip
    - unzip terraform.zip -d /usr/local/bin
    - pip install stig-automator
  script:
    - terraform init -backend=false
    - terraform plan -out=tfplan
    - terraform show -json tfplan > plan.json
    - stig-check plan.json -o json cklb --junit --output-dir stig-results --fail-on CAT_I
  artifacts:
    when: always
    reports:
      junit: stig-results/junit.xml
    paths:
      - plan.json
      - stig-results/
```

## GitHub Actions

```yaml
name: STIG Check

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  stig-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - uses: hashicorp/setup-terraform@v3

      - name: Install stig-check
        run: pip install stig-automator

      - name: Create Terraform plan JSON
        run: |
          terraform init -backend=false
          terraform plan -out=tfplan
          terraform show -json tfplan > plan.json

      - name: Run STIG checks
        run: stig-check plan.json --fail-on CAT_II
```

To upload JSON and STIG Viewer checklist outputs, publish JUnit results in the
GitHub Checks UI, and exempt justified controls:

```yaml
name: STIG Check

on:
  pull_request:

jobs:
  stig-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - uses: hashicorp/setup-terraform@v3

      - name: Install stig-check
        run: pip install stig-automator

      - name: Create Terraform plan JSON
        run: |
          terraform init -backend=false
          terraform plan -out=tfplan
          terraform show -json tfplan > plan.json

      - name: Run STIG checks
        run: |
          stig-check plan.json \
            -o json cklb \
            --junit \
            --output-dir stig-results \
            --fail-on CAT_I \
            --allowed-to-fail V-242382 \
            --allowed-to-fail CNTR-K8-000270

      - name: Publish STIG JUnit results
        uses: dorny/test-reporter@v1
        if: always()
        with:
          name: STIG controls
          path: stig-results/junit.xml
          reporter: java-junit

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: stig-results
          path: |
            plan.json
            stig-results/
```

## Docker Image

Build the repository Dockerfile once in your CI job, then pass an existing
Terraform plan or state JSON file by mounting the workspace into `/work`. The
image entrypoint is `stig-check`, so arguments are passed directly to the CLI.

```bash
docker build -t stig-automator .
docker run --rm -v "$PWD:/work" stig-automator plan.json --fail-on CAT_II
```

To write report artifacts back to the mounted workspace:

```bash
mkdir -p stig-results
docker run --rm -v "$PWD:/work" stig-automator \
  plan.json \
  -o json cklb \
  --output-dir stig-results \
  --fail-on CAT_I
```

## Shared Config File

For repeatable CI behavior, place `.stig-check-config.yml` at the repository
root and keep the pipeline command short:

```yaml
output: [text, json, cklb, junit]
output-dir: stig-results
fail-on: CAT_II
allowed-to-fail:
  - V-242382
```

```bash
stig-check plan.json
```
