"""
Adapter engine that coordinates policy translation across all platforms.

The engine is the main entry point for processing policies and generating
Terraform configurations for all target platforms.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Type

from .models import (
    Policy,
    Platform,
    ResolvedPolicy,
    ResolvedGroup,
    ResolvedService,
    ResolvedMembers,
)
from .registry import Registry
from ..plugins.base import AdapterPlugin
from ..plugins import aws, gcp, azure, paloalto, fortinet, illumio


class AdapterEngine:
    """
    Main engine that coordinates all platform adapters.
    
    Processes policies through the appropriate adapters and generates
    Terraform configurations.
    """

    # Register all available plugins
    PLUGINS: dict[str, Type[AdapterPlugin]] = {
        "aws": aws.AWSAdapter,
        "gcp": gcp.GCPAdapter,
        "azure": azure.AzureAdapter,
        "paloalto": paloalto.PaloAltoAdapter,
        "fortinet": fortinet.FortinetAdapter,
        "illumio": illumio.IllumioAdapter,
    }

    def __init__(self, registry_path: str | Path, config: dict = None):
        self.registry = Registry(registry_path)
        self.config = config or {}
        self.adapters: dict[str, AdapterPlugin] = {}
        
        # Initialize all adapters
        for name, cls in self.PLUGINS.items():
            adapter_config = self.config.get(name, {})
            self.adapters[name] = cls(self.registry, adapter_config)

    def process_policy(self, policy: Policy) -> dict[str, dict[str, str]]:
        """
        Process a policy through all applicable adapters.
        
        Args:
            policy: The policy to process
            
        Returns:
            Dict mapping platform -> scope -> terraform_content
            Example: {"aws": {"prod-account": "resource..."}, "paloalto": {...}}
        """
        results: dict[str, dict[str, str]] = {}

        for target in policy.spec.targets:
            platform_name = target.platform.value
            adapter = self.adapters.get(platform_name)

            if not adapter:
                raise ValueError(f"No adapter for platform: {platform_name}")

            if not adapter.can_handle(policy):
                continue

            # Validate platform-specific constraints
            errors = adapter.validate(policy)
            if errors:
                raise ValueError(f"Validation failed for {platform_name}: {errors}")

            # Process each scope (e.g., each AWS account, each Panorama device group)
            for scope in target.scope:
                # Resolve the policy for this platform and scope
                resolved = self._resolve_policy(policy, adapter, scope)

                # Generate supporting resources (address objects, groups, etc.)
                supporting_tf = adapter.get_supporting_resources(resolved, scope)

                # Generate the main policy resource
                main_tf = adapter.generate_terraform(resolved, scope)

                # Combine
                full_tf = self._combine_terraform(supporting_tf, main_tf, policy, scope)

                if platform_name not in results:
                    results[platform_name] = {}
                results[platform_name][scope] = full_tf

        return results

    def _resolve_policy(
        self, policy: Policy, adapter: AdapterPlugin, scope: str
    ) -> ResolvedPolicy:
        """Resolve all object references in a policy for a specific platform."""
        
        # Resolve source
        if policy.spec.source.group:
            resolved_source = adapter.resolve_group(policy.spec.source.group, scope)
        elif policy.spec.source.cidr:
            resolved_source = ResolvedGroup(
                name="cidr",
                reference=policy.spec.source.cidr,
                reference_type="cidr",
                members=ResolvedMembers(networks=[policy.spec.source.cidr]),
            )
        elif policy.spec.source.any:
            resolved_source = ResolvedGroup(
                name="any",
                reference="any",
                reference_type="any",
            )
        else:
            raise ValueError("Policy source must specify group, cidr, or any")

        # Resolve destination
        if policy.spec.destination.group:
            resolved_dest = adapter.resolve_group(policy.spec.destination.group, scope)
        elif policy.spec.destination.cidr:
            resolved_dest = ResolvedGroup(
                name="cidr",
                reference=policy.spec.destination.cidr,
                reference_type="cidr",
                members=ResolvedMembers(networks=[policy.spec.destination.cidr]),
            )
        elif policy.spec.destination.any:
            resolved_dest = ResolvedGroup(
                name="any",
                reference="any",
                reference_type="any",
            )
        else:
            raise ValueError("Policy destination must specify group, cidr, or any")

        # Resolve services
        resolved_services = []
        for svc in policy.spec.services:
            if isinstance(svc, str):
                resolved_services.append(adapter.resolve_service(svc, scope))
            else:
                # Inline service definition
                from .models import ProtocolDef
                resolved_services.append(
                    ResolvedService(
                        name=f"{svc.protocol}-{svc.port}",
                        protocols=[ProtocolDef(protocol=svc.protocol, port=svc.port)],
                    )
                )

        return ResolvedPolicy(
            name=policy.metadata.name,
            description=policy.spec.description or "",
            ticket=policy.metadata.ticket,
            source=resolved_source,
            destination=resolved_dest,
            services=resolved_services,
            action=policy.spec.action,
            logging=policy.spec.logging,
        )

    def _combine_terraform(
        self, supporting: str, main: str, policy: Policy, scope: str
    ) -> str:
        """Combine supporting resources and main policy into a single TF file."""
        header = f'''# =============================================================================
# Auto-generated by Network Security Policy-as-Code
# Policy: {policy.metadata.name}
# Ticket: {policy.metadata.ticket}
# Requestor: {policy.metadata.requestor}
# Scope: {scope}
# =============================================================================

'''
        parts = [header]
        
        if supporting.strip():
            parts.append("# Supporting Resources\n")
            parts.append(supporting)
            parts.append("\n")

        parts.append("# Policy Resources\n")
        parts.append(main)

        return "".join(parts)

    def process_policies(
        self,
        policy_paths: list[str | Path],
        platforms: list[str] = None,
    ) -> dict[str, dict[str, dict[str, str]]]:
        """
        Process multiple policies.
        
        Args:
            policy_paths: List of policy file paths
            platforms: Optional list of platforms to limit generation to
            
        Returns:
            Dict mapping policy_name -> platform -> scope -> terraform_content
        """
        all_results: dict[str, dict[str, dict[str, str]]] = {}

        for policy_path in policy_paths:
            policy = Policy.from_yaml(policy_path)

            # Filter targets by platform if specified
            if platforms:
                original_targets = policy.spec.targets
                policy.spec.targets = [
                    t for t in original_targets
                    if t.platform.value in platforms
                ]

            if not policy.spec.targets:
                continue

            results = self.process_policy(policy)
            all_results[policy.metadata.name] = results

        return all_results

    def write_terraform(
        self,
        results: dict[str, dict[str, dict[str, str]]],
        output_dir: str | Path,
    ) -> dict[str, list[str]]:
        """
        Write generated Terraform to files.
        
        Args:
            results: Output from process_policies()
            output_dir: Base output directory
            
        Returns:
            Dict mapping platform -> list of workspace names that were affected
        """
        output_path = Path(output_dir)
        affected_workspaces: dict[str, list[str]] = {}

        for policy_name, platforms in results.items():
            for platform, scopes in platforms.items():
                if platform not in affected_workspaces:
                    affected_workspaces[platform] = []

                for scope, tf_content in scopes.items():
                    # Create directory structure
                    scope_dir = output_path / platform / scope
                    scope_dir.mkdir(parents=True, exist_ok=True)

                    # Write the terraform file
                    tf_file = scope_dir / f"{policy_name}.tf"
                    tf_file.write_text(tf_content)

                    # Track affected workspace
                    workspace_name = f"netsec-{platform}-{scope}"
                    if workspace_name not in affected_workspaces[platform]:
                        affected_workspaces[platform].append(workspace_name)

        return affected_workspaces

    def get_workspace_manifest(
        self, affected_workspaces: dict[str, list[str]]
    ) -> list[str]:
        """Flatten affected workspaces into a list for GitHub Actions matrix."""
        workspaces = []
        for platform, workspace_list in affected_workspaces.items():
            workspaces.extend(workspace_list)
        return workspaces
