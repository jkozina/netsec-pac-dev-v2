"""
Base adapter plugin interface.

All platform-specific adapters must inherit from AdapterPlugin
and implement its abstract methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.models import Policy, ResolvedPolicy, ResolvedGroup, ResolvedService
    from ..core.registry import Registry


class AdapterPlugin(ABC):
    """
    Base class for all platform adapters.
    
    Each adapter is responsible for:
    1. Determining if it can handle a policy
    2. Resolving abstract groups/services to platform-specific representations
    3. Generating Terraform for the platform
    """

    # Plugin metadata - subclasses must override
    name: str = ""
    display_name: str = ""
    terraform_provider: str = ""

    def __init__(self, registry: "Registry", config: dict = None):
        """
        Initialize the adapter.
        
        Args:
            registry: The object registry for resolving references
            config: Platform-specific configuration
        """
        self.registry = registry
        self.config = config or {}

    @abstractmethod
    def can_handle(self, policy: "Policy") -> bool:
        """
        Check if this adapter should process the given policy.
        
        Returns True if any of the policy's targets match this platform.
        """
        pass

    @abstractmethod
    def resolve_group(self, group_name: str, scope: str) -> "ResolvedGroup":
        """
        Resolve an abstract group name to a platform-specific representation.
        
        Args:
            group_name: Name of the group in the registry
            scope: The scope within this platform (e.g., device-group, account)
            
        Returns:
            ResolvedGroup containing the platform-specific reference and
            any supporting Terraform resources.
        """
        pass

    @abstractmethod
    def resolve_service(self, service_name: str, scope: str) -> "ResolvedService":
        """
        Resolve an abstract service name to a platform-specific representation.
        
        Args:
            service_name: Name of the service in the registry
            scope: The scope within this platform
            
        Returns:
            ResolvedService containing protocol/port info and any platform-specific
            attributes (like App-ID for Palo Alto).
        """
        pass

    @abstractmethod
    def generate_terraform(self, policy: "ResolvedPolicy", scope: str) -> str:
        """
        Generate Terraform HCL for the resolved policy.
        
        Args:
            policy: The fully resolved policy
            scope: The scope within this platform
            
        Returns:
            Terraform HCL as a string
        """
        pass

    def validate(self, policy: "Policy") -> list[str]:
        """
        Perform platform-specific validation on a policy.
        
        Returns a list of error messages (empty if valid).
        Override in subclasses for custom validation.
        """
        return []

    def get_supporting_resources(self, policy: "ResolvedPolicy", scope: str) -> str:
        """
        Generate Terraform for supporting resources.
        
        Supporting resources are things like address objects, address groups,
        service objects, etc. that must exist before the policy can be created.
        
        Override in subclasses that need supporting resources.
        """
        parts = []
        
        if policy.source.supporting_resources:
            parts.append(policy.source.supporting_resources)
        
        if policy.destination.supporting_resources:
            parts.append(policy.destination.supporting_resources)
        
        return "\n".join(parts)

    # =========================================================================
    # Utility methods available to all adapters
    # =========================================================================

    def _tf_name(self, name: str) -> str:
        """Convert a name to a valid Terraform resource name."""
        return name.replace("-", "_").replace(".", "_").lower()

    def _tf_list(self, items: list[str]) -> str:
        """Format a Python list as a Terraform list."""
        if not items:
            return "[]"
        quoted = [f'"{item}"' for item in items]
        return "[" + ", ".join(quoted) + "]"

    def _tf_multiline_list(self, items: list[str], indent: int = 4) -> str:
        """Format a Python list as a multi-line Terraform list."""
        if not items:
            return "[]"
        spaces = " " * indent
        quoted = [f'{spaces}"{item}",' for item in items]
        return "[\n" + "\n".join(quoted) + "\n" + " " * (indent - 2) + "]"

    def _get_platform_mapping(self, group_name: str) -> dict:
        """Get the platform-specific mapping for a group."""
        group = self.registry.get_group(group_name)
        return group.spec.platform_mapping.get(self.name, {})

    def _get_service_mapping(self, service_name: str) -> dict:
        """Get the platform-specific mapping for a service."""
        service = self.registry.get_service(service_name)
        return service.spec.platform_mapping.get(self.name, {})
