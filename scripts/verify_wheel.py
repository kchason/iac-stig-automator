"""Verify a wheel contains license files and bundled STIG JSON."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path


def main() -> int:
    """Return 0 when the wheel includes the required release files."""
    if len(sys.argv) != 2:
        print("usage: verify_wheel.py DIST.whl", file=sys.stderr)
        return 2
    wheel = Path(sys.argv[1])
    names = zipfile.ZipFile(wheel).namelist()
    missing = [
        suffix
        for suffix in ("/LICENSE", "/NOTICE", "/DISCLAIMER.md")
        if not any(name.endswith(suffix) for name in names)
    ]
    if not any("/stigs/" in name and name.endswith(".json") for name in names):
        missing.append("/stigs/*.json")
    if not any("/mappings/" in name and name.endswith(".json") for name in names):
        missing.append("/mappings/*.json")
    if missing:
        print(f"{wheel} is missing: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
