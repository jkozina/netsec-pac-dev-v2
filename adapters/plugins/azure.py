"""
Azure adapter for Network Security Groups.

Generates Terraform using the hashicorp/azurerm provider.
Supports:
- Application Security Groups (ASG)
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


class AzureAdapter(AdapterPlugin):
    """Adapter for Azure Network Security Groups."""

    name = "azure"
    display_name = "Microsoft Azure"
    terraform_provider = "hashicorp/azurerm"

    def can_handle(self, policy: Policy) -> bool:
        return any(t.platform.value == "azure" for t in policy.spec.targets)

    def resolve_group(self, group_name: str, scope: str) -> ResolvedGroup:
        """Resolve a group to Azure representation."""
        group = self.registry.get_group(group_name)
        mapping = group.spec.platform_mapping.get("azure", {})
        strategy = mapping.get("strategy", "cidr-only")

        resolved_members = self.registry.resolve_group_members(group)

        if strategy == "asg-preferred":
            return self._resolve_asg(group_name, mapping, resolved_members, scope)
        else:
            return self._resolve_cidr(group_name, resolved_members, scope)

    def _resolve_asg(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to Application Security Group reference."""
        asg_config = mapping.get("asg", {})
        asg_name = asg_config.get("name", f"asg-{group_name}")
        resource_group = asg_config.get("resource-group", "rg-network-security")

        # Generate data source for ASG lookup
        tf = f'''
data "azurerm_application_security_group" "{self._tf_name(group_name)}" {{
  name                = "{asg_name}"
  resource_group_name = "{resource_group}"
}}
'''
        return ResolvedGroup(
            name=group_name,
            reference=f"data.azurerm_application_security_group.{self._tf_name(group_name)}.id",
            reference_type="asg",
            members=members,
            supporting_resources=tf,
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
        """Resolve a service to Azure port/protocol representation."""
        service = self.registry.get_service(service_name)

        return ResolvedService(
            name=service_name,
            protocols=service.spec.protocols,
        )

    def generate_terraform(self, policy: ResolvedPolicy, scope: str) -> str:
        """Generate Terraform for Azure NSG rules."""
        tf_parts = []
        priority = 100  # Starting priority

        for i, svc in enumerate(policy.services):
            for j, proto in enumerate(svc.protocols):
                rule_name = f"{policy.name}-{i}-{j}"
                
                # Handle ports
                if proto.port:
                    if isinstance(proto.port, str) and "-" in proto.port:
                        parts = proto.port.split("-")
                        port_range = f"{parts[0]}-{parts[1]}"
                    else:
                        port_range = str(proto.port)
                else:
                    port_range = "*"

                protocol = proto.protocol.upper()
                if protocol == "TCP":
                    protocol = "Tcp"
                elif protocol == "UDP":
                    protocol = "Udp"
                elif protocol == "ICMP":
                    protocol = "Icmp"

                # Source configuration
                if policy.source.reference_type == "asg":
                    source_block = f'source_application_security_group_ids = [{policy.source.reference}]'
                    source_addr = ""
                else:
                    cidrs = policy.source.members.get_all_ipv4()
                    if cidrs:
                        source_block = ""
                        source_addr = f'source_address_prefixes = {self._tf_list(cidrs)}'
                    else:
                        source_block = ""
                        source_addr = 'source_address_prefix = "*"'

                # Destination configuration
                if policy.destination.reference_type == "asg":
                    dest_block = f'destination_application_security_group_ids = [{policy.destination.reference}]'
                    dest_addr = ""
                else:
                    cidrs = policy.destination.members.get_all_ipv4()
                    if cidrs:
                        dest_block = ""
                        dest_addr = f'destination_address_prefixes = {self._tf_list(cidrs)}'
                    else:
                        dest_block = ""
                        dest_addr = 'destination_address_prefix = "*"'

                access = "Allow" if policy.action.value == "allow" else "Deny"

                tf_parts.append(f'''
resource "azurerm_network_security_rule" "{self._tf_name(rule_name)}" {{
  name                        = "{rule_name}"
  priority                    = {priority}
  direction                   = "Inbound"
  access                      = "{access}"
  protocol                    = "{protocol}"
  source_port_range          = "*"
  destination_port_range     = "{port_range}"
  {source_addr}
  {source_block}
  {dest_addr}
  {dest_block}
  resource_group_name         = "TODO_RESOURCE_GROUP"  # Configure based on scope
  network_security_group_name = "TODO_NSG_NAME"  # Configure based on scope
  
  description = "{policy.description} - {policy.ticket}"
}}
''')
                priority += 10

        return "\n".join(tf_parts)
