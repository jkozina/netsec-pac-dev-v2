"""
Palo Alto Networks adapter for Panorama-managed firewalls.

Generates Terraform using the PaloAltoNetworks/panos provider.
Supports:
- Static address groups
- Dynamic address groups (DAG)
- Hybrid (combined) groups
- Security policies
"""

from __future__ import annotations

from ..core.models import (
    Policy,
    ResolvedPolicy,
    ResolvedGroup,
    ResolvedService,
    ResolvedMembers,
    ProtocolDef,
)
from .base import AdapterPlugin


class PaloAltoAdapter(AdapterPlugin):
    """Adapter for Palo Alto Networks Panorama."""

    name = "paloalto"
    display_name = "Palo Alto Networks"
    terraform_provider = "PaloAltoNetworks/panos"

    def can_handle(self, policy: Policy) -> bool:
        return any(t.platform.value == "paloalto" for t in policy.spec.targets)

    def validate(self, policy: Policy) -> list[str]:
        """Validate Palo Alto-specific constraints."""
        errors = []

        # Check that referenced groups have paloalto mappings
        for group_name in policy.get_referenced_groups():
            try:
                group = self.registry.get_group(group_name)
                if "paloalto" not in group.spec.platform_mapping:
                    errors.append(
                        f"Group '{group_name}' has no paloalto platform mapping"
                    )
            except Exception as e:
                errors.append(f"Failed to load group '{group_name}': {e}")

        return errors

    def resolve_group(self, group_name: str, scope: str) -> ResolvedGroup:
        """Resolve a group to Palo Alto address group representation."""
        group = self.registry.get_group(group_name)
        mapping = group.spec.platform_mapping.get("paloalto", {})
        strategy = mapping.get("strategy", "static-only")

        # Get resolved members from registry
        resolved_members = self.registry.resolve_group_members(group)

        if strategy == "dag-only":
            return self._resolve_dag_only(group_name, mapping, scope)
        elif strategy == "static-only":
            return self._resolve_static_only(group_name, mapping, resolved_members, scope)
        elif strategy == "hybrid":
            return self._resolve_hybrid(group_name, mapping, resolved_members, scope)
        else:
            # Default to static
            return self._resolve_static_only(group_name, mapping, resolved_members, scope)

    def _resolve_dag_only(
        self, group_name: str, mapping: dict, scope: str
    ) -> ResolvedGroup:
        """Generate a Dynamic Address Group."""
        dag_config = mapping.get("dag", {})
        dag_name = dag_config.get("name", f"dag-{group_name}")
        match_criteria = dag_config.get("match-criteria", [])

        # Build the match string
        match_str = " or ".join(match_criteria) if match_criteria else f"'{group_name}'"

        tf = f'''
resource "panos_panorama_dynamic_address_group" "{self._tf_name(dag_name)}" {{
  device_group = "{scope}"
  name         = "{dag_name}"
  description  = "Dynamic Address Group: {group_name} - Managed by policy-as-code"
  match        = "{match_str}"
  
  tags = ["policy-as-code", "dynamic"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
'''
        return ResolvedGroup(
            name=group_name,
            reference=dag_name,
            reference_type="dynamic_address_group",
            supporting_resources=tf,
        )

    def _resolve_static_only(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Generate a static address group with address objects."""
        static_config = mapping.get("static", {})
        group_tf_name = static_config.get("name", f"grp-{group_name}")

        tf_parts = []
        address_object_names = []

        # Generate address objects for networks
        for i, network in enumerate(members.networks):
            obj_name = f"net-{group_name}-{i}"
            address_object_names.append(obj_name)
            
            tf_parts.append(f'''
resource "panos_panorama_address_object" "{self._tf_name(obj_name)}" {{
  device_group = "{scope}"
  name         = "{obj_name}"
  description  = "Network for {group_name} - Managed by policy-as-code"
  value        = "{network}"
  
  tags = ["policy-as-code"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        # Generate address objects for hosts
        for host in members.hosts:
            for ip in host.spec.addresses.ipv4:
                obj_name = f"host-{host.metadata.name}"
                if obj_name not in address_object_names:
                    address_object_names.append(obj_name)
                    
                    tf_parts.append(f'''
resource "panos_panorama_address_object" "{self._tf_name(obj_name)}" {{
  device_group = "{scope}"
  name         = "{obj_name}"
  description  = "Host {host.metadata.name} - Managed by policy-as-code"
  value        = "{ip}"
  
  tags = ["policy-as-code"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        # Generate the address group
        if address_object_names:
            member_refs = [
                f"panos_panorama_address_object.{self._tf_name(n)}.name"
                for n in address_object_names
            ]
            members_tf = ",\n    ".join(member_refs)
            
            tf_parts.append(f'''
resource "panos_panorama_address_group" "{self._tf_name(group_tf_name)}" {{
  device_group = "{scope}"
  name         = "{group_tf_name}"
  description  = "Address Group: {group_name} - Managed by policy-as-code"
  
  static_addresses = [
    {members_tf}
  ]
  
  tags = ["policy-as-code"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        return ResolvedGroup(
            name=group_name,
            reference=group_tf_name,
            reference_type="address_group",
            members=members,
            supporting_resources="\n".join(tf_parts),
        )

    def _resolve_hybrid(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Generate a combined group with both DAG and static members."""
        dag_config = mapping.get("dag", {})
        static_config = mapping.get("static", {})
        combined_config = mapping.get("combined", {})

        dag_name = dag_config.get("name", f"dag-{group_name}")
        static_name = static_config.get("name", f"grp-{group_name}-static")
        combined_name = combined_config.get("name", f"grp-{group_name}")

        tf_parts = []

        # Generate DAG
        match_criteria = dag_config.get("match-criteria", [])
        match_str = " or ".join(match_criteria) if match_criteria else f"'{group_name}'"

        tf_parts.append(f'''
resource "panos_panorama_dynamic_address_group" "{self._tf_name(dag_name)}" {{
  device_group = "{scope}"
  name         = "{dag_name}"
  description  = "Dynamic portion of {group_name} - Managed by policy-as-code"
  match        = "{match_str}"
  
  tags = ["policy-as-code", "dynamic"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        # Generate static address objects and group
        address_object_names = []

        for i, network in enumerate(members.networks):
            obj_name = f"net-{group_name}-{i}"
            address_object_names.append(obj_name)
            
            tf_parts.append(f'''
resource "panos_panorama_address_object" "{self._tf_name(obj_name)}" {{
  device_group = "{scope}"
  name         = "{obj_name}"
  description  = "Network for {group_name} - Managed by policy-as-code"
  value        = "{network}"
  
  tags = ["policy-as-code"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        for host in members.hosts:
            for ip in host.spec.addresses.ipv4:
                obj_name = f"host-{host.metadata.name}"
                if obj_name not in address_object_names:
                    address_object_names.append(obj_name)
                    
                    tf_parts.append(f'''
resource "panos_panorama_address_object" "{self._tf_name(obj_name)}" {{
  device_group = "{scope}"
  name         = "{obj_name}"
  description  = "Host {host.metadata.name} - Managed by policy-as-code"
  value        = "{ip}"
  
  tags = ["policy-as-code"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        # Static group
        if address_object_names:
            member_refs = [
                f"panos_panorama_address_object.{self._tf_name(n)}.name"
                for n in address_object_names
            ]
            members_tf = ",\n    ".join(member_refs)
            
            tf_parts.append(f'''
resource "panos_panorama_address_group" "{self._tf_name(static_name)}" {{
  device_group = "{scope}"
  name         = "{static_name}"
  description  = "Static portion of {group_name} - Managed by policy-as-code"
  
  static_addresses = [
    {members_tf}
  ]
  
  tags = ["policy-as-code", "static"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        # Combined group referencing both
        tf_parts.append(f'''
resource "panos_panorama_address_group" "{self._tf_name(combined_name)}" {{
  device_group = "{scope}"
  name         = "{combined_name}"
  description  = "Combined group: {group_name} (DAG + Static) - Managed by policy-as-code"
  
  static_addresses = [
    panos_panorama_dynamic_address_group.{self._tf_name(dag_name)}.name,
    panos_panorama_address_group.{self._tf_name(static_name)}.name,
  ]
  
  tags = ["policy-as-code", "combined"]
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
''')

        return ResolvedGroup(
            name=group_name,
            reference=combined_name,
            reference_type="address_group",
            members=members,
            supporting_resources="\n".join(tf_parts),
        )

    def resolve_service(self, service_name: str, scope: str) -> ResolvedService:
        """Resolve a service to Palo Alto representation."""
        service = self.registry.get_service(service_name)
        mapping = service.spec.platform_mapping.get("paloalto", {})

        if mapping.get("use-app-id", False):
            return ResolvedService(
                name=service_name,
                protocols=service.spec.protocols,
                applications=mapping.get("applications", []),
                service_reference=mapping.get("service", "application-default"),
            )
        else:
            # Use port-based service
            return ResolvedService(
                name=service_name,
                protocols=service.spec.protocols,
                applications=["any"],
                service_reference=None,
            )

    def generate_terraform(self, policy: ResolvedPolicy, scope: str) -> str:
        """Generate Terraform for a Palo Alto security policy."""
        # Build source addresses
        source_addr = f'["{policy.source.reference}"]'
        dest_addr = f'["{policy.destination.reference}"]'

        # Build applications list
        all_apps = set()
        for svc in policy.services:
            all_apps.update(svc.applications)
        apps_list = self._tf_list(list(all_apps))

        # Build services list
        services = []
        for svc in policy.services:
            if svc.service_reference:
                services.append(svc.service_reference)
            else:
                # Build service from protocols
                for proto in svc.protocols:
                    if proto.port:
                        services.append(f"{proto.protocol}/{proto.port}")
        
        if not services:
            services = ["application-default"]
        services_list = self._tf_list(services)

        # Action mapping
        action = "allow" if policy.action.value == "allow" else "deny"

        # Log setting
        log_setting = 'log_setting = "default-logging"' if policy.logging else ""

        return f'''
resource "panos_panorama_security_policy" "{self._tf_name(policy.name)}" {{
  device_group = "{scope}"
  
  rule {{
    name                  = "{policy.name}"
    description           = "{policy.description}"
    source_zones          = ["any"]
    source_addresses      = {source_addr}
    source_users          = ["any"]
    destination_zones     = ["any"]
    destination_addresses = {dest_addr}
    applications          = {apps_list}
    services              = {services_list}
    categories            = ["any"]
    action                = "{action}"
    {log_setting}
    
    tags = ["policy-as-code", "{policy.ticket}"]
  }}
  
  lifecycle {{
    create_before_destroy = true
  }}
}}
'''
