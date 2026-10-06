"""Centralized CLI for STIG compliance checking of Terraform plans."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .config import ConfigError, discover_config_file, load_config
from .manual_overrides import (
    ManualOverride,
    apply_manual_overrides,
    parse_manual_overrides,
)
from .models import CheckResult, Severity
from .output import OutputPathAllocator, render_cklb, render_json, render_junit, render_text
from .plan_parser import filter_by_address, load_plan, walk_resources

# Ensure all modules are registered on import
import stig_automator.modules  # noqa: F401
from .registry import detect_modules, get_all_modules, get_module, registered_names

OUTPUT_FORMATS: list[str] = ["text", "json", "cklb", "junit"]
JUNIT_OUTPUT_FILENAME = "junit.xml"

# ---------------------------------------------------------------------------
# Evaluation engine
# ---------------------------------------------------------------------------

SEV_LEVELS: dict[str, set[Severity]] = {
    "CAT_I": {Severity.CAT_I},
    "CAT_II": {Severity.CAT_I, Severity.CAT_II},
    "CAT_III": {Severity.CAT_I, Severity.CAT_II, Severity.CAT_III},
}

SEVERITY_ALIASES: dict[str, str] = {
    "1": "CAT_I",
    "i": "CAT_I",
    "cat_1": "CAT_I",
    "cat_i": "CAT_I",
    "cat i": "CAT_I",
    "cat-i": "CAT_I",
    "cat 1": "CAT_I",
    "cat-1": "CAT_I",
    "2": "CAT_II",
    "ii": "CAT_II",
    "cat_2": "CAT_II",
    "cat_ii": "CAT_II",
    "cat ii": "CAT_II",
    "cat-ii": "CAT_II",
    "cat 2": "CAT_II",
    "cat-2": "CAT_II",
    "3": "CAT_III",
    "iii": "CAT_III",
    "cat_3": "CAT_III",
    "cat_iii": "CAT_III",
    "cat iii": "CAT_III",
    "cat-iii": "CAT_III",
    "cat 3": "CAT_III",
    "cat-3": "CAT_III",
}

DEFAULT_OPTIONS: dict[str, Any] = {
    "plan_file": None,
    "output": ["text"],
    "output_dir": ".",
    "verbose": False,
    "recommendations": False,
    "no_color": False,
    "modules": None,
    "resources": None,
    "vuln_ids": None,
    "stig_ids": None,
    "severity": None,
    "host_name": "",
    "manual_controls": None,
    "list_modules": False,
    "blank": False,
    "fail_on": "CAT_III",
    "allowed_to_fail": None,
    "junit": False,
}

CONFIG_KEY_ALIASES: dict[str, str] = {
    "plan": "plan_file",
    "plan_file": "plan_file",
    "output": "output",
    "output_dir": "output_dir",
    "verbose": "verbose",
    "recommendations": "recommendations",
    "no_color": "no_color",
    "module": "modules",
    "modules": "modules",
    "resource": "resources",
    "resources": "resources",
    "vuln_id": "vuln_ids",
    "vuln_ids": "vuln_ids",
    "stig_id": "stig_ids",
    "stig_ids": "stig_ids",
    "severity": "severity",
    "host_name": "host_name",
    "manual_controls": "manual_controls",
    "list_modules": "list_modules",
    "blank": "blank",
    "fail_on": "fail_on",
    "allowed_to_fail": "allowed_to_fail",
    "allowed_to_fail_controls": "allowed_to_fail",
    "junit": "junit",
}


def _severity_level(value: Any) -> str:
    """Normalize a severity category for CLI filtering or failure gating."""
    key = str(value).strip().lower().replace("-", "_")
    normalized = SEVERITY_ALIASES.get(key)
    if normalized is None:
        raise argparse.ArgumentTypeError(
            "expected one of CAT_I, CAT_II, CAT_III, CAT I, CAT II, CAT III, 1, 2, or 3"
        )
    return normalized


def _as_string_list(value: Any, option: str) -> list[str] | None:
    """Return a config value as a list of non-empty strings."""
    if value is None:
        return None
    values = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{option} must be a string or list of strings")
        result.append(item.strip())
    return result


def _as_bool(value: Any, option: str) -> bool:
    """Return a config value as a boolean."""
    if isinstance(value, bool):
        return value
    raise ValueError(f"{option} must be true or false")


def _as_optional_string(value: Any, option: str) -> str | None:
    """Return a config value as an optional string."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ValueError(f"{option} must be a string")


def _validate_option(dest: str, value: Any) -> Any:
    """Validate one normalized CLI/config option value."""
    if dest == "output":
        output = _as_string_list(value, dest)
        if not output:
            raise ValueError("output must include at least one format")
        invalid = [item for item in output if item not in OUTPUT_FORMATS]
        if invalid:
            raise ValueError(
                f"output contains unsupported format(s): {', '.join(invalid)}"
            )
        return output
    if dest in {"modules", "resources", "vuln_ids", "stig_ids", "allowed_to_fail"}:
        return _as_string_list(value, dest)
    if dest in {
        "verbose",
        "recommendations",
        "no_color",
        "list_modules",
        "blank",
        "junit",
    }:
        return _as_bool(value, dest)
    if dest in {"severity", "fail_on"}:
        return None if value is None else _severity_level(value)
    if dest in {"plan_file", "output_dir", "host_name", "manual_controls"}:
        return _as_optional_string(value, dest)
    raise ValueError(f"unsupported config option: {dest}")


def _merge_config_args(raw_args: argparse.Namespace, config: dict[str, Any]) -> argparse.Namespace:
    """Merge config file values with parsed CLI values, giving CLI values priority."""
    merged = DEFAULT_OPTIONS.copy()

    for key, value in config.items():
        dest = CONFIG_KEY_ALIASES.get(key)
        if dest is None:
            raise ValueError(f"unsupported config option: {key}")
        merged[dest] = _validate_option(dest, value)

    for dest, value in vars(raw_args).items():
        if dest == "config_file":
            continue
        if dest == "plan_file" and value is None:
            continue
        merged[dest] = _validate_option(dest, value)

    merged["config_file"] = raw_args.config_file
    return argparse.Namespace(**merged)


def _load_config_for_args(args: argparse.Namespace) -> tuple[dict[str, Any], int | None]:
    """Load the auto-discovered or explicitly requested CLI config."""
    try:
        config_path = discover_config_file(args.config_file)
        if config_path is None:
            return {}, None
        return load_config(config_path), None
    except ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return {}, 2


def _allowed_control_matches(results: list[CheckResult], allowed_to_fail: set[str]) -> set[str]:
    """Return allowed-to-fail IDs that matched evaluated controls."""
    matched: set[str] = set()
    for result in results:
        for control_id in (result.control.vuln_id, result.control.stig_id):
            if control_id in allowed_to_fail:
                matched.add(control_id)
    return matched


def _has_blocking_failure(
    results: list[CheckResult],
    *,
    fail_severities: set[Severity],
    allowed_to_fail: set[str],
) -> bool:
    """Return whether evaluated results contain a non-exempt failure."""
    for result in results:
        if result.met or result.not_applicable:
            continue
        if result.control.severity not in fail_severities:
            continue
        if result.control.vuln_id in allowed_to_fail or result.control.stig_id in allowed_to_fail:
            continue
        return True
    return False


def _evaluate(
    module: object,
    resource: dict,
    related: list[dict],
    *,
    vuln_ids: set[str] | None = None,
    stig_ids: set[str] | None = None,
    severities: set[Severity] | None = None,
    csp_inherited_only: bool = False,
) -> list[CheckResult]:
    """Run a module's controls against a single resource.

    Args:
        module: A ``BaseStigModule`` instance.
        resource: Primary Terraform resource dictionary.
        related: Associated child/config resources.
        vuln_ids: If provided, only evaluate these vulnerability IDs.
        stig_ids: If provided, only evaluate these STIG IDs.
        severities: If provided, only evaluate controls at these levels.
        csp_inherited_only: If ``True``, evaluate only CSP-inherited controls.

    Returns:
        List of check results, one per evaluated control.
    """
    controls = module.controls()
    if csp_inherited_only:
        controls = [c for c in controls if c.csp_inherited]
    if vuln_ids:
        controls = [c for c in controls if c.vuln_id in vuln_ids]
    if stig_ids:
        controls = [c for c in controls if c.stig_id in stig_ids]
    if severities:
        controls = [c for c in controls if c.severity in severities]

    results: list[CheckResult] = []
    for control in controls:
        try:
            outcome = control.check(resource, related)
            if len(outcome) == 3:
                met, detail, not_applicable = outcome
            else:
                met, detail = outcome
                not_applicable = False
        except Exception as exc:
            met, detail, not_applicable = False, f"Check raised an exception: {exc}", False
        results.append(CheckResult(control=control, met=met, detail=detail, not_applicable=not_applicable))
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the ``stig-check`` command.

    Returns:
        Configured ``ArgumentParser`` instance.
    """
    p = argparse.ArgumentParser(
        prog="stig-check",
        description=(
            "Evaluate Terraform plan/state JSON files against DISA STIG controls.\n\n"
            "By default, auto-detects which STIG modules apply based on the\n"
            "resource types found in the plan."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Auto-detect resources and evaluate all matching STIGs\n"
            "  stig-check plan.json\n\n"
            "  # Evaluate only the AKS module\n"
            "  stig-check plan.json -m aks\n\n"
            "  # Filter to specific resources by Terraform address\n"
            '  stig-check plan.json -r "module.prod.*"\n\n'
            "  # Show only CAT I and CAT II findings as JSON\n"
            "  stig-check plan.json --severity CAT_II -o json\n\n"
            "  # Generate text + cklb outputs simultaneously\n"
            "  stig-check plan.json -o text cklb --output-dir ./results\n\n"
            "  # Write a JUnit report for CI test report integration\n"
            "  stig-check plan.json --junit --output-dir ./results\n\n"
            "  # Apply reviewer-supplied statuses/comments after automated checks\n"
            "  stig-check plan.json --manual-controls manual-controls.json -o cklb\n\n"
            "  # Generate a no-plan checklist with CSP-inherited controls\n"
            "  stig-check --blank -m aks -o cklb --output-dir ./results\n\n"
            "  # List all available STIG modules\n"
            "  stig-check --list-modules\n\n"
            "Results are a triage aid and are not authorization, accreditation, or audit evidence.\n"
        ),
    )
    p.add_argument(
        "plan_file",
        nargs="?",
        default=None,
        help=(
            "Path to a Terraform plan/state JSON file "
            "(generated via: terraform show -json tfplan > plan.json). "
            "Omit when using --list-modules or --blank."
        ),
    )
    p.add_argument(
        "--config-file",
        metavar="FILE",
        help=(
            "Path to a stig-check config file. If omitted, looks for "
            ".stig-check-config, .stig-check-config.yaml, or "
            ".stig-check-config.yml in the current directory."
        ),
    )
    p.add_argument(
        "-o", "--output",
        nargs="+",
        choices=OUTPUT_FORMATS,
        default=argparse.SUPPRESS,
        metavar="FORMAT",
        help=(
            "Output format(s). One or more of: text, json, cklb, junit. "
            "text is printed to stdout; json and cklb write one file "
            "per resource to --output-dir; junit writes junit.xml. "
            "(default: text)"
        ),
    )
    p.add_argument(
        "--output-dir",
        default=argparse.SUPPRESS,
        metavar="DIR",
        help=(
            "Directory for json, cklb, and junit output files "
            "(default: current directory)."
        ),
    )
    p.add_argument(
        "--junit",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Also write a consolidated JUnit XML report to "
            f"{JUNIT_OUTPUT_FILENAME} in --output-dir."
        ),
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show description text for every control, not just failing ones.",
    )
    p.add_argument(
        "--recommendations",
        action="store_true",
        help=(
            "Include recommended corrective action and Terraform remediation "
            "guidance in text output and cklb comments."
        ),
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable ANSI colour codes in text output.",
    )
    p.add_argument(
        "-m", "--module",
        action="append",
        dest="modules",
        default=argparse.SUPPRESS,
        metavar="MODULE",
        help=(
            "Restrict evaluation to specific STIG module(s). Repeatable. "
            "If omitted, modules are auto-detected from the plan. "
            "Use --list-modules to see available names."
        ),
    )
    p.add_argument(
        "-r", "--resource",
        action="append",
        dest="resources",
        default=argparse.SUPPRESS,
        metavar="ADDRESS",
        help=(
            "Filter to specific Terraform resource addresses. "
            "Supports glob patterns (e.g. 'module.prod.*'). Repeatable."
        ),
    )
    p.add_argument(
        "--vuln-id",
        action="append",
        dest="vuln_ids",
        default=argparse.SUPPRESS,
        metavar="ID",
        help="Evaluate only the specified vulnerability ID(s). Repeatable.",
    )
    p.add_argument(
        "--stig-id",
        action="append",
        dest="stig_ids",
        default=argparse.SUPPRESS,
        metavar="ID",
        help="Evaluate only the specified STIG ID(s). Repeatable.",
    )
    p.add_argument(
        "--severity",
        type=_severity_level,
        default=argparse.SUPPRESS,
        metavar="LEVEL",
        help=(
            "Minimum severity level to report. "
            "CAT_I = high only, CAT_II = high + medium, CAT_III = all (default: all)."
        ),
    )
    p.add_argument(
        "--fail-on",
        type=_severity_level,
        default=argparse.SUPPRESS,
        metavar="LEVEL",
        help=(
            "Exit 1 only for non-exempt findings at this severity or higher. "
            "Accepts CAT_I/CAT_II/CAT_III, CAT I/CAT II/CAT III, or 1/2/3 "
            "(default: CAT_III)."
        ),
    )
    p.add_argument(
        "--allowed-to-fail",
        action="append",
        dest="allowed_to_fail",
        default=argparse.SUPPRESS,
        metavar="CONTROL_ID",
        help=(
            "Exclude a justified failing control ID from --fail-on gating. "
            "Matches vulnerability IDs or STIG IDs. Repeatable."
        ),
    )
    p.add_argument(
        "--host-name",
        default=argparse.SUPPRESS,
        metavar="NAME",
        help="Hostname to include in cklb target_data (default: Terraform resource address).",
    )
    p.add_argument(
        "--manual-controls",
        default=argparse.SUPPRESS,
        metavar="FILE",
        help=(
            "Path to a JSON file of manual control overrides with Control ID, "
            "Status, and Comments fields. Status must be Not a Finding, Open, "
            "or Not Applicable."
        ),
    )
    p.add_argument(
        "--list-modules",
        action="store_true",
        default=argparse.SUPPRESS,
        help="List all available STIG modules and exit.",
    )
    p.add_argument(
        "--blank",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Generate output without a plan file using only controls inherited "
            "from the cloud service provider. If -m is omitted, all modules "
            "with inherited controls are used."
        ),
    )
    return p


def _run_list_modules() -> int:
    """Print all registered modules and return an exit code."""
    modules = get_all_modules()
    if not modules:
        print("No STIG modules registered.", file=sys.stderr)
        return 1
    print("Available STIG modules:\n")
    for mod in sorted(modules, key=lambda m: m.name):
        print(f"  {mod.name:<20s} {mod.description}")
        print(f"  {'':20s} Resource type: {mod.resource_type}")
        print()
    return 0


def _resolve_modules(
    args: argparse.Namespace,
    all_resources: list[dict],
) -> tuple[list, int | None]:
    """Determine which modules to run and return them with an optional error code.

    Args:
        args: Parsed CLI arguments.
        all_resources: Flat list of resources from the plan.

    Returns:
        ``(modules_list, error_code)`` — *error_code* is ``None`` on success.
    """
    if args.modules:
        modules = []
        for name in args.modules:
            try:
                modules.append(get_module(name))
            except KeyError:
                print(
                    f"Error: unknown module '{name}'. "
                    f"Available: {', '.join(registered_names())}",
                    file=sys.stderr,
                )
                return [], 2
        return modules, None

    resource_types: set[str] = {r.get("type") for r in all_resources}
    modules = detect_modules(resource_types)
    if not modules:
        print(
            "No matching STIG modules for the resource types in this plan.\n"
            f"Resource types found: {', '.join(sorted(resource_types))}\n"
            f"Available modules: {', '.join(registered_names())}",
            file=sys.stderr,
        )
        return [], 1
    return modules, None


def _write_file(
    out_dir: Path,
    allocator: OutputPathAllocator,
    resource: dict,
    ext: str,
    content: str,
) -> None:
    """Write a file named after *resource* into *out_dir*.

    Args:
        out_dir: Target directory (must exist).
        allocator: Filename allocator for this command invocation.
        resource: Terraform resource dict used to derive the filename.
        ext: File extension including the dot (e.g. ``".json"``).
        content: File content to write.
    """
    out_path: Path = out_dir / allocator.filename_for(resource, ext)
    out_path.write_text(content, encoding="utf-8")
    print(f"Wrote {out_path}", file=sys.stderr)


def _write_named_file(out_dir: Path, filename: str, content: str) -> None:
    """Write a fixed-name output file into *out_dir*."""
    out_path = out_dir / filename
    out_path.write_text(content, encoding="utf-8")
    print(f"Wrote {out_path}", file=sys.stderr)


def _load_manual_overrides(path: str | None) -> tuple[dict[str, ManualOverride], int | None]:
    """Load manual control overrides from a JSON file."""
    if not path:
        return {}, None

    override_path = Path(path)
    if not override_path.exists():
        print(f"Error: manual controls file not found: {override_path}", file=sys.stderr)
        return {}, 2

    try:
        data = json.loads(override_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Error: could not parse manual controls JSON - {exc}", file=sys.stderr)
        return {}, 2

    overrides, warnings = parse_manual_overrides(data)
    for warning in warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    return {override.control_id: override for override in overrides}, None


def _blank_resource(module: object) -> dict:
    """Return a synthetic target resource for no-plan blank output."""
    return {
        "address": f"{module.name}.csp_inherited_controls",
        "name": f"{module.name}-csp-inherited-controls",
        "type": module.resource_type,
        "values": {},
    }


def _resolve_blank_modules(args: argparse.Namespace) -> tuple[list, int | None]:
    """Resolve modules for ``--blank`` output."""
    if args.modules:
        modules = []
        for name in args.modules:
            try:
                modules.append(get_module(name))
            except KeyError:
                print(
                    f"Error: unknown module '{name}'. "
                    f"Available: {', '.join(registered_names())}",
                    file=sys.stderr,
                )
                return [], 2
        return modules, None
    return [m for m in get_all_modules() if any(c.csp_inherited for c in m.controls())], None


def _run_blank(
    args: argparse.Namespace,
    *,
    formats: list[str],
    vuln_ids: set[str] | None,
    stig_ids: set[str] | None,
    severities: set[Severity] | None,
    fail_severities: set[Severity],
    allowed_to_fail: set[str],
    use_color: bool,
    manual_overrides: dict[str, ManualOverride],
) -> int:
    """Generate output for CSP-inherited controls without loading a plan."""
    if args.resources:
        print("Error: --resource cannot be used with --blank.", file=sys.stderr)
        return 2

    modules, err = _resolve_blank_modules(args)
    if err is not None:
        return err
    if not modules:
        print("No STIG modules with CSP-inherited controls are registered.", file=sys.stderr)
        return 1

    wants_text: bool = "text" in formats
    wants_json: bool = "json" in formats
    wants_cklb: bool = "cklb" in formats
    wants_junit: bool = "junit" in formats

    out_dir: Path = Path(args.output_dir)
    if (wants_json or wants_cklb or wants_junit) and not out_dir.is_dir():
        out_dir.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    rendered_any = False
    matched_manual_ids: set[str] = set()
    matched_allowed_ids: set[str] = set()
    output_paths = OutputPathAllocator()
    junit_suites: list[tuple[str, dict, list[CheckResult]]] = []
    for mod in modules:
        resource = _blank_resource(mod)
        results = _evaluate(
            mod, resource, [],
            vuln_ids=vuln_ids, stig_ids=stig_ids, severities=severities,
            csp_inherited_only=True,
        )
        if not results:
            continue
        matched_manual_ids.update(apply_manual_overrides(results, manual_overrides))
        matched_allowed_ids.update(_allowed_control_matches(results, allowed_to_fail))
        rendered_any = True
        if wants_junit:
            junit_suites.append((mod.report_title, resource, results))

        if _has_blocking_failure(
            results,
            fail_severities=fail_severities,
            allowed_to_fail=allowed_to_fail,
        ):
            exit_code = 1

        if wants_text:
            print(render_text(
                mod.report_title, resource, results,
                verbose=args.verbose, use_color=use_color,
                include_recommendations=args.recommendations,
            ))

        if wants_json:
            doc: dict = render_json(resource, results)
            _write_file(out_dir, output_paths, resource, ".json", json.dumps(doc, indent=2))

        if wants_cklb:
            doc = render_cklb(
                mod, resource, results,
                host_name=args.host_name,
                include_recommendations=args.recommendations,
                target_comments=(
                    "Generated by stig-automator from CSP-inherited controls "
                    "without Terraform plan analysis"
                ),
            )
            _write_file(out_dir, output_paths, resource, ".cklb", json.dumps(doc, indent=2))

    if not rendered_any:
        print("No CSP-inherited controls found for the given criteria.", file=sys.stderr)
        return 1
    if wants_junit:
        _write_named_file(out_dir, JUNIT_OUTPUT_FILENAME, render_junit(junit_suites))
    _warn_unmatched_manual_overrides(manual_overrides, matched_manual_ids)
    _warn_unmatched_allowed_to_fail(allowed_to_fail, matched_allowed_ids)
    return exit_code


def _warn_unmatched_manual_overrides(
    manual_overrides: dict[str, ManualOverride],
    matched_manual_ids: set[str],
) -> None:
    """Warn about manual control IDs that matched no evaluated controls."""
    for control_id in manual_overrides:
        if control_id not in matched_manual_ids:
            print(
                f"Warning: manual controls Control ID {control_id!r} "
                "did not match any evaluated control.",
                file=sys.stderr,
            )


def _warn_unmatched_allowed_to_fail(
    allowed_to_fail: set[str],
    matched_allowed_ids: set[str],
) -> None:
    """Warn about allowed-to-fail IDs that matched no evaluated controls."""
    for control_id in sorted(allowed_to_fail):
        if control_id not in matched_allowed_ids:
            print(
                f"Warning: allowed-to-fail control ID {control_id!r} "
                "did not match any evaluated control.",
                file=sys.stderr,
            )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``stig-check``.

    Args:
        argv: Command-line arguments.  Defaults to ``sys.argv[1:]``.

    Returns:
        Exit code: 0 = all met, 1 = findings, 2 = errors.
    """
    parser: argparse.ArgumentParser = build_parser()
    raw_args: argparse.Namespace = parser.parse_args(argv)
    config, err = _load_config_for_args(raw_args)
    if err is not None:
        return err
    try:
        args: argparse.Namespace = _merge_config_args(raw_args, config)
    except (argparse.ArgumentTypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.list_modules:
        return _run_list_modules()

    # Deduplicate while preserving order
    formats: list[str] = list(dict.fromkeys(args.output + (["junit"] if args.junit else [])))
    wants_text: bool = "text" in formats
    wants_json: bool = "json" in formats
    wants_cklb: bool = "cklb" in formats
    wants_junit: bool = "junit" in formats

    vuln_ids: set[str] | None = set(args.vuln_ids) if args.vuln_ids else None
    stig_ids: set[str] | None = set(args.stig_ids) if args.stig_ids else None
    severities: set[Severity] | None = SEV_LEVELS.get(args.severity) if args.severity else None
    fail_severities: set[Severity] = SEV_LEVELS[args.fail_on]
    allowed_to_fail: set[str] = set(args.allowed_to_fail or [])

    use_color: bool = not args.no_color and sys.stdout.isatty()
    manual_overrides, err = _load_manual_overrides(args.manual_controls)
    if err is not None:
        return err

    if args.blank:
        return _run_blank(
            args,
            formats=formats,
            vuln_ids=vuln_ids,
            stig_ids=stig_ids,
            severities=severities,
            fail_severities=fail_severities,
            allowed_to_fail=allowed_to_fail,
            use_color=use_color,
            manual_overrides=manual_overrides,
        )

    if not args.plan_file:
        parser.error("plan_file is required unless --list-modules or --blank is specified.")

    plan_path: Path = Path(args.plan_file)
    if not plan_path.exists():
        print(f"Error: file not found: {plan_path}", file=sys.stderr)
        return 2

    try:
        plan: dict = load_plan(plan_path)
    except json.JSONDecodeError as exc:
        print(f"Error: could not parse JSON - {exc}", file=sys.stderr)
        return 2

    all_resources: list[dict] = walk_resources(plan)
    selected_resources: list[dict] = all_resources

    if args.resources:
        selected_resources = filter_by_address(all_resources, args.resources)

    if not selected_resources:
        print("No resources found matching the given criteria.", file=sys.stderr)
        return 1

    modules, err = _resolve_modules(args, selected_resources)
    if err is not None:
        return err

    out_dir: Path = Path(args.output_dir)
    if (wants_json or wants_cklb or wants_junit) and not out_dir.is_dir():
        out_dir.mkdir(parents=True, exist_ok=True)

    exit_code: int = 0
    matched_manual_ids: set[str] = set()
    matched_allowed_ids: set[str] = set()
    output_paths = OutputPathAllocator()
    junit_suites: list[tuple[str, dict, list[CheckResult]]] = []

    for mod in modules:
        resource_pairs = mod.find_resources(all_resources)
        if args.resources:
            selected_primary_ids = {
                id(resource)
                for resource in filter_by_address(
                    [resource for resource, _related in resource_pairs],
                    args.resources,
                )
            }
            resource_pairs = [
                (resource, related)
                for resource, related in resource_pairs
                if id(resource) in selected_primary_ids
            ]
        if not resource_pairs:
            continue

        for resource, related in resource_pairs:
            results: list[CheckResult] = _evaluate(
                mod, resource, related,
                vuln_ids=vuln_ids, stig_ids=stig_ids, severities=severities,
            )
            if not results:
                continue
            matched_manual_ids.update(apply_manual_overrides(results, manual_overrides))
            matched_allowed_ids.update(_allowed_control_matches(results, allowed_to_fail))
            if wants_junit:
                junit_suites.append((mod.report_title, resource, results))

            if _has_blocking_failure(
                results,
                fail_severities=fail_severities,
                allowed_to_fail=allowed_to_fail,
            ):
                exit_code = 1

            if wants_text:
                print(render_text(
                    mod.report_title, resource, results,
                    verbose=args.verbose, use_color=use_color,
                    include_recommendations=args.recommendations,
                ))

            if wants_json:
                doc: dict = render_json(resource, results)
                _write_file(out_dir, output_paths, resource, ".json", json.dumps(doc, indent=2))

            if wants_cklb:
                doc = render_cklb(
                    mod, resource, results,
                    host_name=args.host_name,
                    include_recommendations=args.recommendations,
                )
                _write_file(out_dir, output_paths, resource, ".cklb", json.dumps(doc, indent=2))

    if wants_junit and junit_suites:
        _write_named_file(out_dir, JUNIT_OUTPUT_FILENAME, render_junit(junit_suites))
    _warn_unmatched_manual_overrides(manual_overrides, matched_manual_ids)
    _warn_unmatched_allowed_to_fail(allowed_to_fail, matched_allowed_ids)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
