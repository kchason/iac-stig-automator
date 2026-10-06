"""Import official DISA XCCDF rule metadata into module control JSON files.

The runtime CLI must stay fully offline, so this script consumes a local STIG
ZIP downloaded from Cyber Exchange and writes committed JSON catalogs under
``src/stig_automator/modules/stigs``. Terraform check mappings live separately
under ``src/stig_automator/modules/mappings`` and are not modified by this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
from zipfile import ZipFile
import xml.etree.ElementTree as ET


SEVERITY_MAP = {
    "high": "CAT_I",
    "medium": "CAT_II",
    "low": "CAT_III",
}
DESCRIPTION_FIELDS = {
    "VulnDiscussion": "description",
    "FalsePositives": "false_positives",
    "FalseNegatives": "false_negatives",
    "Documentable": "documentable",
    "Mitigations": "mitigations",
    "PotentialImpacts": "potential_impacts",
    "ThirdPartyTools": "third_party_tools",
    "MitigationControl": "mitigation_control",
    "Responsibility": "responsibility",
    "SeverityOverrideGuidance": "security_override_guidance",
}


def _text(element: ET.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    return element.text


def _namespace(root: ET.Element) -> dict[str, str]:
    if not root.tag.startswith("{"):
        return {"x": ""}
    return {"x": root.tag.split("}", 1)[0][1:]}


def _description_section(description: str, section: str) -> str:
    pattern = rf"<{section}>(.*?)</{section}>"
    match = re.search(pattern, description, flags=re.DOTALL)
    if match:
        return match.group(1)
    if re.search(rf"<{section}\s*/>", description):
        return ""
    return ""


def _rule_metadata(group: ET.Element, ns: dict[str, str]) -> dict[str, Any]:
    rule = group.find("x:Rule", ns)
    if rule is None:
        raise ValueError(f"Group {group.attrib.get('id', '<unknown>')} has no Rule element")

    raw_description = _text(rule.find("x:description", ns))
    metadata: dict[str, Any] = {
        "vuln_id": group.attrib["id"],
        "stig_id": _text(rule.find("x:version", ns)),
        "severity": SEVERITY_MAP[rule.attrib["severity"]],
        "title": _text(rule.find("x:title", ns)),
        "rule_id": rule.attrib["id"],
        "rule_version": _text(rule.find("x:version", ns)),
        "group_id": group.attrib["id"],
        "group_title": _text(group.find("x:title", ns)),
        "cci": [
            _text(ident)
            for ident in rule.findall("x:ident", ns)
            if ident.attrib.get("system") == "http://cyber.mil/cci"
        ],
        "fix_text": _text(rule.find("x:fixtext", ns)),
    }
    for xml_name, json_name in DESCRIPTION_FIELDS.items():
        metadata[json_name] = _description_section(raw_description, xml_name)

    check = rule.find("x:check", ns)
    check_content = check.find("x:check-content", ns) if check is not None else None
    check_content_ref = check.find("x:check-content-ref", ns) if check is not None else None
    metadata["check_content"] = _text(check_content)
    metadata["check_content_ref"] = dict(check_content_ref.attrib) if check_content_ref is not None else {}
    return metadata


def _load_official_metadata(stig_zip: Path) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    with ZipFile(stig_zip) as archive:
        xccdf_names = [name for name in archive.namelist() if name.endswith("Manual-xccdf.xml")]
        if len(xccdf_names) != 1:
            raise ValueError(f"Expected one Manual-xccdf.xml in {stig_zip}, found {len(xccdf_names)}")
        xccdf_name = xccdf_names[0]
        root = ET.fromstring(archive.read(xccdf_name))

    ns = _namespace(root)
    benchmark = {
        "benchmark_id": root.attrib["id"],
        "benchmark_title": _text(root.find("x:title", ns)),
        "version": _text(root.find("x:version", ns)),
        "release_info": _text(root.find("x:plain-text[@id='release-info']", ns)),
        "xccdf_file": Path(xccdf_name).name,
    }
    controls = {
        metadata["vuln_id"]: metadata
        for metadata in (
            _rule_metadata(group, ns)
            for group in root.findall("x:Group", ns)
        )
    }
    return benchmark, controls


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def import_controls(
    *,
    stig_zip: Path,
    controls_json: Path,
    output_json: Path,
    manifest_json: Path | None,
    source_url: str,
    full_catalog: bool = False,
) -> None:
    benchmark, official_controls = _load_official_metadata(stig_zip)
    if full_catalog:
        imported_controls = [dict(metadata) for metadata in official_controls.values()]
    else:
        existing_controls = json.loads(controls_json.read_text(encoding="utf-8"))
        imported_controls = []
        missing_ids = []

        for existing in existing_controls:
            vuln_id = existing["vuln_id"]
            official = official_controls.get(vuln_id)
            if official is None:
                missing_ids.append(vuln_id)
                continue
            imported_controls.append(dict(official))

        if missing_ids:
            joined = ", ".join(missing_ids)
            raise ValueError(f"{controls_json} contains control IDs not found in {stig_zip}: {joined}")

    output_json.write_text(
        json.dumps(imported_controls, indent=2) + "\n",
        encoding="utf-8",
    )

    if manifest_json is not None:
        manifest = {
            "source_url": source_url,
            "source_archive": stig_zip.name,
            "source_sha256": _sha256(stig_zip),
            "imported_control_count": len(imported_controls),
            "official_control_count": len(official_controls),
            **benchmark,
        }
        manifest_json.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stig-zip", required=True, type=Path, help="Local official DISA STIG ZIP")
    parser.add_argument("--controls-json", required=True, type=Path, help="Existing module controls JSON")
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Output path. Defaults to updating --controls-json in place.",
    )
    parser.add_argument("--manifest-json", type=Path, help="Optional import manifest output path")
    parser.add_argument("--source-url", default="", help="Official source URL for the manifest")
    parser.add_argument(
        "--full-catalog",
        action="store_true",
        help="Import every XCCDF Group in archive order instead of updating existing vuln_id entries only.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output_json = args.output_json or args.controls_json
    import_controls(
        stig_zip=args.stig_zip,
        controls_json=args.controls_json,
        output_json=output_json,
        manifest_json=args.manifest_json,
        source_url=args.source_url,
        full_catalog=args.full_catalog,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
