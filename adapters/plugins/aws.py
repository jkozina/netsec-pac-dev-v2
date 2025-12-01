"""
AWS adapter for Security Groups.

Generates Terraform using the hashicorp/aws provider.
Supports:
- Security group rules
- Security group references
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


class AWSAdapter(AdapterPlugin):
    """Adapter for AWS Security Groups."""

    name = "aws"
    display_name = "Amazon Web Services"
    terraform_provider = "hashicorp/aws"

    def can_handle(self, policy: Policy) -> bool:
        return any(t.platform.value == "aws" for t in policy.spec.targets)

    def validate(self, policy: Policy) -> list[str]:
        """Validate AWS-specific constraints."""
        errors = []
        
        # AWS security groups have limits on rules
        # This is a simplified check
        
        return errors

    def resolve_group(self, group_name: str, scope: str) -> ResolvedGroup:
        """Resolve a group to AWS security group or CIDR representation."""
        group = self.registry.get_group(group_name)
        mapping = group.spec.platform_mapping.get("aws", {})
        strategy = mapping.get("strategy", "cidr-only")

        resolved_members = self.registry.resolve_group_members(group)

        if strategy == "security-group-preferred":
            return self._resolve_security_group(group_name, mapping, resolved_members, scope)
        else:
            return self._resolve_cidr(group_name, resolved_members, scope)

    def _resolve_security_group(
        self,
        group_name: str,
        mapping: dict,
        members: ResolvedMembers,
        scope: str,
    ) -> ResolvedGroup:
        """Resolve to security group reference with CIDR fallback."""
        sg_config = mapping.get("security-group", {})
        tag_key = sg_config.get("tag-key", "netsec:group")
        tag_value = sg_config.get("tag-value", group_name)

        # Generate data source to look up the security group
        tf = f'''
data "aws_security_group" "{self._tf_name(group_name)}" {{
  tags = {{
    "{tag_key}" = "{tag_value}"
  }}
}}
'''
        return ResolvedGroup(
            name=group_name,
            reference=f"data.aws_security_group.{self._tf_name(group_name)}.id",
            reference_type="security_group",
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
        cidrs = members.get_all_ipv4()

        return ResolvedGroup(
            name=group_name,
            reference="cidr",
            reference_type="cidr",
            members=members,
        )

    def resolve_service(self, service_name: str, scope: str) -> ResolvedService:
        """Resolve a service to AWS port/protocol representation."""
        service = self.registry.get_service(service_name)

        return ResolvedService(
            name=service_name,
            protocols=service.spec.protocols,
        )

    def generate_terraform(self, policy: ResolvedPolicy, scope: str) -> str:
        """Generate Terraform for AWS security group rules."""
        tf_parts = []

        # Generate a rule for each service/protocol
        for i, svc in enumerate(policy.services):
            for j, proto in enumerate(svc.protocols):
                rule_name = f"{policy.name}-{i}-{j}"
                
                # Handle port ranges
                from_port = proto.port
                to_port = proto.port
                
                if isinstance(proto.port, str) and "-" in proto.port:
                    parts = proto.port.split("-")
                    from_port = int(parts[0])
                    to_port = int(parts[1])
                elif proto.port:
                    from_port = to_port = int(proto.port)
                else:
                    from_port = to_port = 0

                protocol = proto.protocol
                if protocol == "icmp":
                    from_port = -1
                    to_port = -1

                # Determine source/destination based on action
                if policy.source.reference_type == "security_group":
                    source_block = f'source_security_group_id = {policy.source.reference}'
                else:
                    cidrs = policy.source.members.get_all_ipv4()
                    if cidrs:
                        source_block = f'cidr_blocks = {self._tf_list(cidrs)}'
                    else:
                        source_block = 'cidr_blocks = ["0.0.0.0/0"]'

                # Generate ingress rule on destination security group
                tf_parts.append(f'''
resource "aws_security_group_rule" "{self._tf_name(rule_name)}" {{
  type              = "ingress"
  from_port         = {from_port}
  to_port           = {to_port}
  protocol          = "{protocol}"
  {source_block}
  security_group_id = "TODO_DESTINATION_SG_ID"  # Configure based on scope
  
  description = "{policy.description} - {policy.ticket}"
}}
''')

        return "\n".join(tf_parts)
