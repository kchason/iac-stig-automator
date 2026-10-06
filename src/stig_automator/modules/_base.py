"""Abstract base class for STIG compliance modules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import StigControl
from ..plan_parser import filter_by_type
from ..util import get_nested


class BaseStigModule(ABC):
    """Abstract base class for STIG compliance modules.

    Subclasses must set the class-level metadata attributes and
    implement :meth:`controls`.  The default :meth:`find_resources`
    handles both simple (no related types) and complex (with related
    types) resource matching.

    Class Attributes:
        name: Short identifier used on the CLI (e.g. ``"aks"``).
        description: Human-readable one-liner shown in ``--list-modules``.
        resource_type: Primary Terraform resource type this module evaluates.
        additional_resource_types: Optional alternate primary types for auto-detection.
        related_resource_types: Terraform types for child/config resources.
        report_title: Title used in text report headers.
        stig_benchmark_id: XCCDF benchmark identifier for cklb export.
        stig_benchmark_title: Full STIG benchmark name for cklb export.
        stig_version: STIG version string for cklb export.
        stig_release_info: STIG release string for cklb export.
    """

    name: str
    description: str
    resource_type: str
    additional_resource_types: set[str] = set()
    related_resource_types: set[str] = set()
    report_title: str

    # STIG benchmark metadata for cklb export
    stig_benchmark_id: str = ""
    stig_benchmark_title: str = ""
    stig_version: str = "1"
    stig_release_info: str = "Release: 1"

    @abstractmethod
    def controls(self) -> list[StigControl]:
        """Return the ordered list of STIG controls for this module."""
        ...

    def find_resources(
        self, all_resources: list[dict],
    ) -> list[tuple[dict, list[dict]]]:
        """Find primary and related resources from a flat resource list.

        Returns a list of ``(primary_resource, [related_resources])`` tuples.
        The default implementation matches related resources by
        ``server_id``, ``server_name``, or Terraform address prefix
        proximity.

        Args:
            all_resources: Flat list of all resources from the plan.

        Returns:
            List of (primary, related) tuples.
        """
        primaries: list[dict] = filter_by_type(all_resources, self.resource_type)
        if not self.related_resource_types:
            return [(p, []) for p in primaries]

        related: list[dict] = [
            r for r in all_resources if r.get("type") in self.related_resource_types
        ]

        result: list[tuple[dict, list[dict]]] = []
        for primary in primaries:
            primary_addr: str = primary.get("address", "")
            primary_id: str = get_nested(primary, "values", "id", default="")
            primary_name: str = get_nested(primary, "values", "name", default="")
            matched: list[dict] = []
            for rel in related:
                rel_server_id: str = get_nested(rel, "values", "server_id", default="")
                rel_server_name: str = get_nested(rel, "values", "server_name", default="")
                rel_addr: str = rel.get("address", "")
                if (
                    (primary_id and rel_server_id == primary_id)
                    or (rel_server_name and rel_server_name == primary_name)
                    or (
                        primary_addr
                        and rel_addr.startswith(
                            primary_addr.rsplit(".", 1)[0] + "."
                        )
                    )
                ):
                    matched.append(rel)
                else:
                    matched.append(rel)
            result.append((primary, matched))
        return result
