"""
Fortinet adapter for FortiGate/FortiManager.

Generates Terraform using the fortinetdev/fortios provider.
Supports:
- Address objects
- Address groups
- Firewall policies
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


class FortinetAdapter(AdapterPlugin):
    """Adapter for Fortinet FortiGate/FortiManager."""

    name = "fortinet"
    display_name = "Fortinet"
    terraform_provider = "fortinetdev/fortios"

    def can_handle(self, policy: Policy) -> bool:
        return any(t.platform.value == "fortinet" for t in policy.spec.targets)

    def resolve_group(self, group_name: str, scope: str) -> ResolvedGroup:
        """Resolve a group to Fortinet address group representation."""
        group = self.registry.get_group(group_name)
        mapping = group.spec.platform_mapping.get("fortinet", {})

        resolved_members = self.registry.resolve_group_members(group)

        return self._resolve_address_group(group_name, mapping, resolved_members, scope)

    def _resolve_address_group(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Generate Fortinet address objects and group."""
        addr_group_config = mapping.get("address-group", {})
        group_tf_name = addr_group_config.get("name", f"grp-{group_name}")

        tf_parts = []
        address_object_names = []

        # Generate address objects for networks
        for i, network in enumerate(members.networks):
            obj_name = f"net-{group_name}-{i}"
            address_object_names.append(obj_name)
            
            # Determine if it's a subnet or single IP
            if "/" in network:
                from ipaddress import ip_network
                net = ip_network(network, strict=False)
                tf_parts.append(f'''
resource "fortios_firewall_address" "{self._tf_name(obj_name)}" {{
  name    = "{obj_name}"
  type    = "ipmask"
  subnet  = "{network}"
  comment = "Network for {group_name} - Managed by policy-as-code"
}}
''')
            else:
                tf_parts.append(f'''
resource "fortios_firewall_address" "{self._tf_name(obj_name)}" {{
  name       = "{obj_name}"
  type       = "ipmask"
  subnet     = "{network}/32"
  comment    = "Address for {group_name} - Managed by policy-as-code"
}}
''')

        # Generate address objects for hosts
        for host in members.hosts:
            for ip in host.spec.addresses.ipv4:
                obj_name = f"host-{host.metadata.name}"
                if obj_name not in address_object_names:
                    address_object_names.append(obj_name)
                    
                    tf_parts.append(f'''
resource "fortios_firewall_address" "{self._tf_name(obj_name)}" {{
  name    = "{obj_name}"
  type    = "ipmask"
  subnet  = "{ip}/32"
  comment = "Host {host.metadata.name} - Managed by policy-as-code"
}}
''')

            # Also add FQDN entries if available
            for fqdn in host.spec.addresses.fqdn:
                obj_name = f"fqdn-{host.metadata.name}"
                if obj_name not in address_object_names:
                    address_object_names.append(obj_name)
                    
                    tf_parts.append(f'''
resource "fortios_firewall_address" "{self._tf_name(obj_name)}" {{
  name    = "{obj_name}"
  type    = "fqdn"
  fqdn    = "{fqdn}"
  comment = "FQDN for {host.metadata.name} - Managed by policy-as-code"
}}
''')

        # Generate the address group
        if address_object_names:
            members_block = []
            for name in address_object_names:
                members_block.append(f'''
  member {{
    name = fortios_firewall_address.{self._tf_name(name)}.name
  }}''')
            members_str = "\n".join(members_block)

            tf_parts.append(f'''
resource "fortios_firewall_addrgrp" "{self._tf_name(group_tf_name)}" {{
  name    = "{group_tf_name}"
  comment = "Address Group: {group_name} - Managed by policy-as-code"
{members_str}
}}
''')

        return ResolvedGroup(
            name=group_name,
            reference=group_tf_name,
            reference_type="address_group",
            members=members,
            supporting_resources="\n".join(tf_parts),
        )

    def resolve_service(self, service_name: str, scope: str) -> ResolvedService:
        """Resolve a service to Fortinet representation."""
        service = self.registry.get_service(service_name)
        mapping = service.spec.platform_mapping.get("fortinet", {})

        # Check if there's a predefined FortiGate service
        predefined = mapping.get("service-name")

        return ResolvedService(
            name=service_name,
            protocols=service.spec.protocols,
            service_reference=predefined,
        )

    def generate_terraform(self, policy: ResolvedPolicy, scope: str) -> str:
        """Generate Terraform for Fortinet firewall policy."""
        # Build service block
        service_names = []
        for svc in policy.services:
            if svc.service_reference:
                service_names.append(svc.service_reference)
            else:
                # Need to create custom service or use port
                for proto in svc.protocols:
                    if proto.protocol.lower() == "tcp":
                        service_names.append(f"TCP_{proto.port}")
                    elif proto.protocol.lower() == "udp":
                        service_names.append(f"UDP_{proto.port}")
                    else:
                        service_names.append("ALL")

        if not service_names:
            service_names = ["ALL"]

        service_block = []
        for svc_name in service_names:
            service_block.append(f'''
  service {{
    name = "{svc_name}"
  }}''')
        service_str = "\n".join(service_block)

        # Action
        action = "accept" if policy.action.value == "allow" else "deny"

        # Logging
        logtraffic = "all" if policy.logging else "disable"

        return f'''
resource "fortios_firewall_policy" "{self._tf_name(policy.name)}" {{
  name     = "{policy.name}"
  action   = "{action}"
  schedule = "always"
  
  srcintf {{
    name = "any"
  }}
  
  dstintf {{
    name = "any"
  }}
  
  srcaddr {{
    name = "{policy.source.reference}"
  }}
  
  dstaddr {{
    name = "{policy.destination.reference}"
  }}
  
{service_str}
  
  logtraffic = "{logtraffic}"
  comments   = "{policy.description} - {policy.ticket}"
  
  nat = "disable"
}}
'''
