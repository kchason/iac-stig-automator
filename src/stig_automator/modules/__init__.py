"""Auto-import all STIG modules in this package for registration."""

from importlib import import_module
from pathlib import Path

_pkg_dir: Path = Path(__file__).parent
for _f in sorted(_pkg_dir.glob("*.py")):
    if _f.name.startswith("_"):
        continue
    import_module(f".{_f.stem}", __package__)
