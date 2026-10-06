"""STIG module registry with auto-detection support."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .modules._base import BaseStigModule

_REGISTRY: dict[str, type[BaseStigModule]] = {}


def register(cls: type[BaseStigModule]) -> type[BaseStigModule]:
    """Class decorator that registers a STIG module.

    Args:
        cls: The module class to register.

    Returns:
        The same class, unmodified.
    """
    _REGISTRY[cls.name] = cls
    return cls


def get_module(name: str) -> BaseStigModule:
    """Return an instance of the named module.

    Args:
        name: Registered module name (e.g. ``"aks"``).

    Returns:
        A new instance of the module.

    Raises:
        KeyError: If no module with *name* is registered.
    """
    return _REGISTRY[name]()


def get_all_modules() -> list[BaseStigModule]:
    """Return instances of every registered module.

    Returns:
        List of all registered module instances.
    """
    return [cls() for cls in _REGISTRY.values()]


def detect_modules(resource_types: set[str]) -> list[BaseStigModule]:
    """Return module instances whose primary resource type is in *resource_types*.

    Args:
        resource_types: Set of Terraform resource type strings found in a plan.

    Returns:
        List of matching module instances.
    """
    return [
        cls()
        for cls in _REGISTRY.values()
        if cls.resource_type in resource_types
        or cls.additional_resource_types & resource_types
    ]


def registered_names() -> list[str]:
    """Return sorted list of all registered module names.

    Returns:
        Alphabetically sorted module name strings.
    """
    return sorted(_REGISTRY)
