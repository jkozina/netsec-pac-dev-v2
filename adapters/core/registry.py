"""
Registry module for loading and resolving network objects.

The Registry class provides access to hosts, groups, and services
defined in the registry directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional
import yaml

from .models import (
    Host,
    Group,
    Service,
    Policy,
    ResolvedMembers,
)


class RegistryError(Exception):
    """Raised when there's an issue with the registry."""
    pass


class ObjectNotFoundError(RegistryError):
    """Raised when a referenced object doesn't exist."""
    pass


class Registry:
    """
    Central registry for all network objects.
    
    Provides loading, caching, and resolution of hosts, groups, and services.
    """

    def __init__(self, registry_path: str | Path):
        self.registry_path = Path(registry_path)
        self._hosts_cache: dict[str, Host] = {}
        self._groups_cache: dict[str, Group] = {}
        self._services_cache: dict[str, Service] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Lazy-load all registry objects."""
        if self._loaded:
            return

        # Load hosts
        hosts_path = self.registry_path / "hosts"
        if hosts_path.exists():
            for yaml_file in hosts_path.glob("**/*.yaml"):
                try:
                    host = Host.from_yaml(yaml_file)
                    self._hosts_cache[host.metadata.name] = host
                except Exception as e:
                    raise RegistryError(f"Failed to load host {yaml_file}: {e}") from e

        # Load groups
        groups_path = self.registry_path / "groups"
        if groups_path.exists():
            for yaml_file in groups_path.glob("**/*.yaml"):
                try:
                    group = Group.from_yaml(yaml_file)
                    self._groups_cache[group.metadata.name] = group
                except Exception as e:
                    raise RegistryError(f"Failed to load group {yaml_file}: {e}") from e

        # Load services
        services_path = self.registry_path / "services"
        if services_path.exists():
            for yaml_file in services_path.glob("**/*.yaml"):
                try:
                    service = Service.from_yaml(yaml_file)
                    self._services_cache[service.metadata.name] = service
                except Exception as e:
                    raise RegistryError(f"Failed to load service {yaml_file}: {e}") from e

        self._loaded = True

    def get_host(self, name: str) -> Host:
        """Get a host by name."""
        self._ensure_loaded()
        
        # Handle host/name format
        if name.startswith("host/"):
            name = name[5:]
        
        if name not in self._hosts_cache:
            raise ObjectNotFoundError(f"Host not found: {name}")
        return self._hosts_cache[name]

    def get_group(self, name: str) -> Group:
        """Get a group by name."""
        self._ensure_loaded()
        if name not in self._groups_cache:
            raise ObjectNotFoundError(f"Group not found: {name}")
        return self._groups_cache[name]

    def get_service(self, name: str) -> Service:
        """Get a service by name."""
        self._ensure_loaded()
        if name not in self._services_cache:
            raise ObjectNotFoundError(f"Service not found: {name}")
        return self._services_cache[name]

    def all_hosts(self) -> Iterator[Host]:
        """Iterate over all hosts."""
        self._ensure_loaded()
        yield from self._hosts_cache.values()

    def all_groups(self) -> Iterator[Group]:
        """Iterate over all groups."""
        self._ensure_loaded()
        yield from self._groups_cache.values()

    def all_services(self) -> Iterator[Service]:
        """Iterate over all services."""
        self._ensure_loaded()
        yield from self._services_cache.values()

    def load_host(self, path: str | Path) -> Host:
        """Load a host from a specific file path."""
        return Host.from_yaml(path)

    def load_group(self, path: str | Path) -> Group:
        """Load a group from a specific file path."""
        return Group.from_yaml(path)

    def load_service(self, path: str | Path) -> Service:
        """Load a service from a specific file path."""
        return Service.from_yaml(path)

    def load_policy(self, path: str | Path) -> Policy:
        """Load a policy from a file path."""
        return Policy.from_yaml(path)

    def resolve_group_members(self, group: Group) -> ResolvedMembers:
        """
        Resolve all members of a group, including dynamic matches.
        
        This expands:
        - Static host references to actual Host objects
        - Dynamic membership by matching host labels
        - Nested group references
        """
        self._ensure_loaded()
        members = ResolvedMembers()

        # Add static host references
        for host_ref in group.spec.membership.static:
            try:
                host = self.get_host(host_ref)
                members.add_host(host)
            except ObjectNotFoundError:
                # Log warning but continue
                pass

        # Add network CIDRs
        for network in group.spec.membership.networks:
            members.add_network(network)

        # Resolve dynamic membership
        if group.spec.membership.dynamic and group.spec.membership.dynamic.match_labels:
            match_labels = group.spec.membership.dynamic.match_labels
            for host in self.all_hosts():
                if self._labels_match(host.spec.labels, match_labels):
                    members.add_host(host)

        # Resolve nested groups
        for nested_group_name in group.spec.membership.groups:
            try:
                nested_group = self.get_group(nested_group_name)
                nested_members = self.resolve_group_members(nested_group)
                for host in nested_members.hosts:
                    members.add_host(host)
                for network in nested_members.networks:
                    members.add_network(network)
            except ObjectNotFoundError:
                pass

        return members

    def _labels_match(self, host_labels: dict[str, str], match_labels: dict[str, str]) -> bool:
        """Check if host labels satisfy match criteria."""
        for key, value in match_labels.items():
            if host_labels.get(key) != value:
                return False
        return True

    def validate_policy_references(self, policy: Policy) -> list[str]:
        """
        Validate that all references in a policy exist.
        
        Returns a list of error messages (empty if valid).
        """
        self._ensure_loaded()
        errors = []

        # Check source reference
        if policy.spec.source.group:
            if policy.spec.source.group not in self._groups_cache:
                errors.append(f"Source group not found: {policy.spec.source.group}")
        elif policy.spec.source.host:
            host_name = policy.spec.source.host
            if host_name.startswith("host/"):
                host_name = host_name[5:]
            if host_name not in self._hosts_cache:
                errors.append(f"Source host not found: {policy.spec.source.host}")

        # Check destination reference
        if policy.spec.destination.group:
            if policy.spec.destination.group not in self._groups_cache:
                errors.append(f"Destination group not found: {policy.spec.destination.group}")
        elif policy.spec.destination.host:
            host_name = policy.spec.destination.host
            if host_name.startswith("host/"):
                host_name = host_name[5:]
            if host_name not in self._hosts_cache:
                errors.append(f"Destination host not found: {policy.spec.destination.host}")

        # Check service references
        for svc in policy.spec.services:
            if isinstance(svc, str):
                if svc not in self._services_cache:
                    errors.append(f"Service not found: {svc}")

        return errors

    def find_groups_matching_host(self, host: Host) -> list[Group]:
        """Find all groups that would include this host via dynamic membership."""
        self._ensure_loaded()
        matching_groups = []

        for group in self.all_groups():
            if group.matches_dynamically(host.spec.labels):
                matching_groups.append(group)

        return matching_groups
