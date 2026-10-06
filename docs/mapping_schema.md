# Control Mapping Schema

STIG Automator keeps raw STIG content separate from local evaluation behavior:

- `src/stig_automator/modules/stigs/` contains imported DISA/STIG checklist data.
- `src/stig_automator/modules/mappings/` contains local behavior, evidence, and remediation mappings.

Each control mapping must define exactly one behavior path:

- `automatic_platform_text` for inherited, managed platform, manual-scope, or not-applicable text.
- `validation_function_name` for Terraform plan validation callbacks implemented in Python.

The machine-readable schema is `schemas/control_mapping.schema.json`. Validate
all control mapping files with:

```bash
python3 scripts/validate_control_mappings.py
```

## Platform or inherited controls

Use platform mappings when the control is satisfied or explained without reading Terraform plan values.

```json
{
  "automatic_platform_text": "{vuln_id} ({title}) is inherited from the managed service.",
  "evidence_key": "inherited",
  "cklb_status": "not_a_finding",
  "include_in_blank_cklb": true
}
```

Fields:

- `automatic_platform_text`: Detail text template. Supported variables are module-specific, but all modules support `{vuln_id}` and `{title}`. EKS also supports `{compute}`.
- `evidence_key`: Optional key into the module's evidence JSON.
- `cklb_status`: One of `not_a_finding`, `open`, or `not_applicable`.
- `include_in_blank_cklb`: `true` when `stig-check --blank` should include this control.

## Validation controls

Use validation mappings when a Terraform plan/static state check should evaluate the control.

```json
{
  "validation_function_name": "rbac_enabled",
  "remediation_key": "rbac_enabled"
}
```

Fields:

- `validation_function_name`: Key in the module's Python callback registry.
- `remediation_key`: Optional evidence key used to generate Terraform remediation comments for open findings.

Validation mappings cannot set `include_in_blank_cklb` because blank CKLB output has no plan data to evaluate.

## Defaults

Kubernetes modules support a `default` mapping for controls not listed explicitly:

```json
{
  "default": {
    "automatic_platform_text": "AKS managed-service baseline evidence applied for {vuln_id} ({title}).",
    "evidence_key": "managed_default",
    "cklb_status": "not_a_finding",
    "include_in_blank_cklb": true
  },
  "controls": {}
}
```

The default is only used when a control ID is absent from `controls`; explicit entries do not inherit default fields.

## Validation rules

The loader fails fast when:

- A mapping defines both `automatic_platform_text` and `validation_function_name`.
- A mapping defines neither behavior field.
- A callback name is not registered by the module.
- An evidence or remediation key does not exist in the module evidence JSON.
- A validation mapping sets `include_in_blank_cklb`.
- A platform mapping uses an unsupported `cklb_status`.
