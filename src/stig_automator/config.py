"""Configuration loading for the ``stig-check`` CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONFIG_FILENAMES: tuple[str, ...] = (
    ".stig-check-config",
    ".stig-check-config.yaml",
    ".stig-check-config.yml",
)


class ConfigError(ValueError):
    """Raised when a ``stig-check`` config file cannot be used."""


def discover_config_file(explicit_path: str | None, root: Path | None = None) -> Path | None:
    """Return the explicit or first auto-discovered config file path."""
    if explicit_path:
        path = Path(explicit_path)
        if not path.exists():
            raise ConfigError(f"config file not found: {path}")
        return path

    search_root = root or Path.cwd()
    for name in CONFIG_FILENAMES:
        path = search_root / name
        if path.exists():
            return path
    return None


def load_config(path: Path) -> dict[str, Any]:
    """Load a JSON or simple YAML config file into a normalized dictionary."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read config file {path}: {exc}") from exc

    if not text.strip():
        return {}

    try:
        data = _load_config_text(text)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"could not parse config file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must contain an object")

    return {_normalize_key(str(key)): value for key, value in data.items()}


def _load_config_text(text: str) -> Any:
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return json.loads(text)
    return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset needed for project configuration.

    The project has no runtime dependencies, so this intentionally supports
    top-level ``key: value`` pairs plus top-level lists written as ``- item``.
    """
    data: dict[str, Any] = {}
    list_key: str | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line).rstrip()
        if not line.strip():
            continue

        if line[:1].isspace():
            stripped = line.strip()
            if list_key is None or not stripped.startswith("- "):
                raise ConfigError(f"unsupported YAML indentation on line {line_number}")
            data[list_key].append(_parse_scalar(stripped[2:].strip()))
            continue

        if ":" not in line:
            raise ConfigError(f"expected 'key: value' on line {line_number}")

        key, value = line.split(":", 1)
        clean_key = _normalize_key(key.strip())
        if not clean_key:
            raise ConfigError(f"empty key on line {line_number}")

        raw_value = value.strip()
        if raw_value:
            data[clean_key] = _parse_scalar(raw_value)
            list_key = None
        else:
            data[clean_key] = []
            list_key = clean_key

    return data


def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _parse_scalar(value: str) -> Any:
    if not value:
        return ""
    if value[0] == value[-1:] and value[0] in {"'", '"'}:
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    return value


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace("-", "_").replace(" ", "_")
