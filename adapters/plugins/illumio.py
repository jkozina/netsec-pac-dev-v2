"""
Illumio adapter for Policy Compute Engine (PCE).

Generates Terraform using the illumio/illumio-core provider.
Supports:
- Label-based rules
- IP Lists
- Rulesets
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


class IllumioAdapter(AdapterPlugin):
    """Adapter for Illumio PCE."""

    name = "illumio"
    display_name = "Illumio"
    terraform_provider = "illumio/illumio-core"

    def can_handle(self, policy: Policy) -> bool:
        return any(t.platform.value == "illumio" for t in policy.spec.targets)

    def resolve_group(self, group_name: str, scope: str) -> ResolvedGroup:
        """Resolve a group to Illumio representation."""
        group = self.registry.get_group(group_name)
        mapping = group.spec.platform_mapping.get("illumio", {})
        strategy = mapping.get("strategy", "label-based")

        resolved_members = self.registry.resolve_group_members(group)

        if strategy == "label-based":
            return self._resolve_labels(group_name, mapping, resolved_members, scope)
        elif strategy == "ip-list":
            return self._resolve_ip_list(group_name, mapping, resolved_members, scope)
        else:
            return self._resolve_hybrid(group_name, mapping, resolved_members, scope)

    def _resolve_labels(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to Illumio label references."""
        labels = mapping.get("labels", [])
        
        tf_parts = []
        label_refs = []

        for label in labels:
            key = label.get("key", "app")
            value = label.get("value", group_name)
            tf_name = f"label_{self._tf_name(group_name)}_{key}"
            
            # Data source to look up existing label
            tf_parts.append(f'''
data "illumio-core_labels" "{tf_name}" {{
  key   = "{key}"
  value = "{value}"
}}
''')
            label_refs.append(f"data.illumio-core_labels.{tf_name}.items[0].href")

        return ResolvedGroup(
            name=group_name,
            reference=",".join(label_refs) if label_refs else group_name,
            reference_type="label",
            members=members,
            supporting_resources="\n".join(tf_parts),
        )

    def _resolve_ip_list(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to Illumio IP List."""
        ip_list_config = mapping.get("ip-list", {})
        ip_list_name = ip_list_config.get("name", f"ipl-{group_name}")

        cidrs = members.get_all_ipv4()
        
        # Build IP ranges block
        ip_ranges = []
        for cidr in cidrs:
            if "/" in cidr:
                # It's a CIDR
                from ipaddress import ip_network
                network = ip_network(cidr, strict=False)
                ip_ranges.append(f'''
  ip_ranges {{
    from_ip = "{network.network_address}"
    to_ip   = "{network.broadcast_address}"
  }}''')
            else:
                # Single IP
                ip_ranges.append(f'''
  ip_ranges {{
    from_ip = "{cidr}"
  }}''')

        ip_ranges_str = "\n".join(ip_ranges)

        tf = f'''
resource "illumio-core_ip_list" "{self._tf_name(ip_list_name)}" {{
  name        = "{ip_list_name}"
  description = "IP List for {group_name} - Managed by policy-as-code"
{ip_ranges_str}
}}
'''
        return ResolvedGroup(
            name=group_name,
            reference=f"illumio-core_ip_list.{self._tf_name(ip_list_name)}.href",
            reference_type="ip_list",
            members=members,
            supporting_resources=tf,
        )

    def _resolve_hybrid(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to both labels and IP list."""
        # Combine label and IP list resolution
        label_result = self._resolve_labels(group_name, mapping, members, scope)
        ip_list_result = self._resolve_ip_list(group_name, mapping, members, scope)

        combined_tf = label_result.supporting_resources + "\n" + ip_list_result.supporting_resources

        return ResolvedGroup(
            name=group_name,
            reference=f"{label_result.reference},{ip_list_result.reference}",
            reference_type="hybrid",
            members=members,
            supporting_resources=combined_tf,
        )

    def resolve_service(self, service_name: str, scope: str) -> ResolvedService:
        """Resolve a service to Illumio representation."""
        service = self.registry.get_service(service_name)
        mapping = service.spec.platform_mapping.get("illumio", {})

        return ResolvedService(
            name=service_name,
            protocols=service.spec.protocols,
        )

    def generate_terraform(self, policy: ResolvedPolicy, scope: str) -> str:
        """Generate Terraform for Illumio ruleset."""
        # Build ingress services
        ingress_services = []
        for svc in policy.services:
            for proto in svc.protocols:
                proto_num = {"tcp": 6, "udp": 17, "icmp": 1}.get(proto.protocol.lower(), 6)
                
                if proto.port:
                    if isinstance(proto.port, str) and "-" in proto.port:
                        parts = proto.port.split("-")
                        ingress_services.append(f'''
      ingress_services {{
        proto   = {proto_num}
        port    = {parts[0]}
        to_port = {parts[1]}
      }}''')
                    else:
                        ingress_services.append(f'''
      ingress_services {{
        proto = {proto_num}
        port  = {proto.port}
      }}''')
                else:
                    ingress_services.append(f'''
      ingress_services {{
        proto = {proto_num}
      }}''')

        ingress_services_str = "\n".join(ingress_services)

        # Build providers (destinations)
        if policy.destination.reference_type == "label":
            providers_block = f'''
    providers {{
      label {{
        href = {policy.destination.reference.split(",")[0]}
      }}
    }}'''
        elif policy.destination.reference_type == "ip_list":
            providers_block = f'''
    providers {{
      ip_list {{
        href = {policy.destination.reference}
      }}
    }}'''
        else:
            providers_block = '''
    providers {
      actors = "ams"  # All workloads
    }'''

        # Build consumers (sources)
        if policy.source.reference_type == "label":
            consumers_block = f'''
    consumers {{
      label {{
        href = {policy.source.reference.split(",")[0]}
      }}
    }}'''
        elif policy.source.reference_type == "ip_list":
            consumers_block = f'''
    consumers {{
      ip_list {{
        href = {policy.source.reference}
      }}
    }}'''
        else:
            consumers_block = '''
    consumers {
      actors = "ams"  # All workloads
    }'''

        return f'''
resource "illumio-core_rule_set" "{self._tf_name(policy.name)}" {{
  name        = "{policy.name}"
  description = "{policy.description} - {policy.ticket}"
  enabled     = true

  scopes {{
    # Define scope based on PCE organization
  }}

  rule {{
    enabled                         = true
    description                     = "{policy.description}"
    resolve_labels_as_workloads     = true
    
{providers_block}

{consumers_block}

{ingress_services_str}
  }}
}}
'''
