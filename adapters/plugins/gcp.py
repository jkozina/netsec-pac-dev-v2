"""
GCP adapter for Firewall Rules.

Generates Terraform using the hashicorp/google provider.
Supports:
- Network tags
- Service accounts
- CIDR-based rules
"""

from __future__ import annotations

from ..core.models import (
    Policy,
    ResolvedPolicy,
    ResolvedGroup,
    ResolvedService,
    ResolvedMembers,
)
from .base import AdapterPlugin


class GCPAdapter(AdapterPlugin):
    """Adapter for GCP Firewall Rules."""

    name = "gcp"
    display_name = "Google Cloud Platform"
    terraform_provider = "hashicorp/google"

    def can_handle(self, policy: Policy) -> bool:
        return any(t.platform.value == "gcp" for t in policy.spec.targets)

    def resolve_group(self, group_name: str, scope: str) -> ResolvedGroup:
        """Resolve a group to GCP representation."""
        group = self.registry.get_group(group_name)
        mapping = group.spec.platform_mapping.get("gcp", {})
        strategy = mapping.get("strategy", "cidr-only")

        resolved_members = self.registry.resolve_group_members(group)

        if strategy == "network-tag-preferred":
            return self._resolve_network_tag(group_name, mapping, resolved_members, scope)
        elif strategy == "service-account-preferred":
            return self._resolve_service_account(group_name, mapping, resolved_members, scope)
        else:
            return self._resolve_cidr(group_name, resolved_members, scope)

    def _resolve_network_tag(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to network tag reference."""
        tag_config = mapping.get("network-tag", {})
        tag = tag_config.get("tag", group_name)

        return ResolvedGroup(
            name=group_name,
            reference=tag,
            reference_type="network_tag",
            members=members,
        )

    def _resolve_service_account(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to service account reference."""
        sa_config = mapping.get("service-account", {})
        email = sa_config.get("email", f"{group_name}@{scope}.iam.gserviceaccount.com")

        return ResolvedGroup(
            name=group_name,
            reference=email,
            reference_type="service_account",
            members=members,
        )

    def _resolve_cidr(
        self,
        group_name: str,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to CIDR blocks."""
        return ResolvedGroup(
            name=group_name,
            reference="cidr",
            reference_type="cidr",
            members=members,
        )

    def resolve_service(self, service_name: str, scope: str) -> ResolvedService:
        """Resolve a service to GCP port/protocol representation."""
        service = self.registry.get_service(service_name)

        return ResolvedService(
            name=service_name,
            protocols=service.spec.protocols,
        )

    def generate_terraform(self, policy: ResolvedPolicy, scope: str) -> str:
        """Generate Terraform for GCP firewall rules."""
        # Build allow block for each service
        allow_blocks = []
        for svc in policy.services:
            for proto in svc.protocols:
                ports = []
                if proto.port:
                    if isinstance(proto.port, str) and "-" in proto.port:
                        ports.append(proto.port)
                    else:
                        ports.append(str(proto.port))
                
                if ports:
                    allow_blocks.append(f'''
  allow {{
    protocol = "{proto.protocol}"
    ports    = {self._tf_list(ports)}
  }}''')
                else:
                    allow_blocks.append(f'''
  allow {{
    protocol = "{proto.protocol}"
  }}''')

        allow_str = "\n".join(allow_blocks)

        # Build source/target based on reference type
        if policy.source.reference_type == "network_tag":
            source_block = f'source_tags = ["{policy.source.reference}"]'
        elif policy.source.reference_type == "service_account":
            source_block = f'source_service_accounts = ["{policy.source.reference}"]'
        else:
            cidrs = policy.source.members.get_all_ipv4()
            if cidrs:
                source_block = f'source_ranges = {self._tf_list(cidrs)}'
            else:
                source_block = 'source_ranges = ["0.0.0.0/0"]'

        if policy.destination.reference_type == "network_tag":
            target_block = f'target_tags = ["{policy.destination.reference}"]'
        elif policy.destination.reference_type == "service_account":
            target_block = f'target_service_accounts = ["{policy.destination.reference}"]'
        else:
            target_block = ""

        # Direction - GCP firewall rules are either INGRESS or EGRESS
        direction = "INGRESS"

        return f'''
resource "google_compute_firewall" "{self._tf_name(policy.name)}" {{
  name        = "{policy.name}"
  network     = "default"  # Configure based on scope
  project     = "{scope}"
  description = "{policy.description} - {policy.ticket}"
  direction   = "{direction}"
  
  {source_block}
  {target_block}
{allow_str}
  
  # Logging
  log_config {{
    metadata = "{'"INCLUDE_ALL_METADATA"' if policy.logging else '"EXCLUDE_ALL_METADATA"'}"
  }}
}}
'''
