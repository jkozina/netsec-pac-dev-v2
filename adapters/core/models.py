"""
Core data models for the policy-as-code framework.

These Pydantic models represent the canonical schema for policies,
groups, hosts, and services.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator
import yaml
from pathlib import Path


class ApiVersion(str, Enum):
    V1 = "netsec/v1"


class Platform(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    PALOALTO = "paloalto"
    FORTINET = "fortinet"
    ILLUMIO = "illumio"


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"


# ============================================================================
# Policy Models
# ============================================================================

class PolicyMetadata(BaseModel):
    name: str
    requestor: str
    ticket: str
    environment: Optional[Environment] = None
    expiration: Optional[str] = None
    labels: dict[str, str] = Field(default_factory=dict)


class Endpoint(BaseModel):
    group: Optional[str] = None
    host: Optional[str] = None
    cidr: Optional[str] = None
    any: Optional[bool] = None

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            import ipaddress
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid CIDR: {v}") from e
        return v

    def get_type(self) -> str:
        if self.group:
            return "group"
        elif self.host:
            return "host"
        elif self.cidr:
            return "cidr"
        elif self.any:
            return "any"
        return "unknown"

    def get_reference(self) -> str:
        return self.group or self.host or self.cidr or "any"


class InlineService(BaseModel):
    protocol: str
    port: int | str
    description: Optional[str] = None


class Target(BaseModel):
    platform: Platform
    scope: list[str]


class GuardrailOverrides(BaseModel):
    skip_review: bool = Field(default=False, alias="skip-review")
    justification: Optional[str] = None

    class Config:
        populate_by_name = True


class PolicySpec(BaseModel):
    description: Optional[str] = None
    source: Endpoint
    destination: Endpoint
    services: list[str | InlineService]
    action: Action
    logging: bool = True
    targets: list[Target]
    guardrails: Optional[GuardrailOverrides] = None


class Policy(BaseModel):
    apiVersion: ApiVersion
    kind: str = "NetworkPolicy"
    metadata: PolicyMetadata
    spec: PolicySpec

    @classmethod
    def from_yaml(cls, path: Path | str) -> Policy:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def get_referenced_groups(self) -> set[str]:
        groups = set()
        if self.spec.source.group:
            groups.add(self.spec.source.group)
        if self.spec.destination.group:
            groups.add(self.spec.destination.group)
        return groups

    def get_referenced_services(self) -> set[str]:
        services = set()
        for svc in self.spec.services:
            if isinstance(svc, str):
                services.add(svc)
        return services


# ============================================================================
# Host Models
# ============================================================================

class HostAddresses(BaseModel):
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    fqdn: list[str] = Field(default_factory=list)


class PlatformRefs(BaseModel):
    aws: Optional[dict[str, Any]] = None
    gcp: Optional[dict[str, Any]] = None
    azure: Optional[dict[str, Any]] = None
    illumio: Optional[dict[str, Any]] = None
    paloalto: Optional[dict[str, Any]] = None


class HostSpec(BaseModel):
    description: Optional[str] = None
    environment: Optional[Environment] = None
    location: Optional[str] = None
    addresses: HostAddresses
    platform_refs: Optional[PlatformRefs] = Field(default=None, alias="platform-refs")
    labels: dict[str, str] = Field(default_factory=dict)

    class Config:
        populate_by_name = True


class HostMetadata(BaseModel):
    name: str
    owner: Optional[str] = None
    cmdb_id: Optional[str] = Field(default=None, alias="cmdb-id")
    description: Optional[str] = None

    class Config:
        populate_by_name = True


class Host(BaseModel):
    apiVersion: ApiVersion
    kind: str = "Host"
    metadata: HostMetadata
    spec: HostSpec

    @classmethod
    def from_yaml(cls, path: Path | str) -> Host:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)


# ============================================================================
# Group Models
# ============================================================================

class DynamicMembership(BaseModel):
    match_labels: dict[str, str] = Field(default_factory=dict, alias="match-labels")

    class Config:
        populate_by_name = True


class Membership(BaseModel):
    static: list[str] = Field(default_factory=list)
    dynamic: Optional[DynamicMembership] = None
    networks: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)


class GroupSpec(BaseModel):
    description: Optional[str] = None
    membership: Membership
    platform_mapping: dict[str, Any] = Field(default_factory=dict, alias="platform-mapping")

    class Config:
        populate_by_name = True


class GroupMetadata(BaseModel):
    name: str
    owner: Optional[str] = None
    description: Optional[str] = None
    labels: dict[str, str] = Field(default_factory=dict)


class Group(BaseModel):
    apiVersion: ApiVersion
    kind: str = "Group"
    metadata: GroupMetadata
    spec: GroupSpec

    @classmethod
    def from_yaml(cls, path: Path | str) -> Group:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def matches_dynamically(self, labels: dict[str, str]) -> bool:
        """Check if given labels would match this group's dynamic membership."""
        if not self.spec.membership.dynamic:
            return False

        match_labels = self.spec.membership.dynamic.match_labels
        if not match_labels:
            return False

        for key, value in match_labels.items():
            if labels.get(key) != value:
                return False
        return True


# ============================================================================
# Service Models
# ============================================================================

class ProtocolDef(BaseModel):
    protocol: str
    port: Optional[int | str] = None
    description: Optional[str] = None


class ServiceSpec(BaseModel):
    description: Optional[str] = None
    protocols: list[ProtocolDef]
    platform_mapping: dict[str, Any] = Field(default_factory=dict, alias="platform-mapping")

    class Config:
        populate_by_name = True


class ServiceMetadata(BaseModel):
    name: str
    owner: Optional[str] = None
    description: Optional[str] = None


class Service(BaseModel):
    apiVersion: ApiVersion
    kind: str = "Service"
    metadata: ServiceMetadata
    spec: ServiceSpec

    @classmethod
    def from_yaml(cls, path: Path | str) -> Service:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)


# ============================================================================
# Resolved Models (output of resolution phase)
# ============================================================================

class ResolvedMembers(BaseModel):
    """Resolved group membership with concrete IPs and references."""
    hosts: list[Host] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)
    platform_reference: Optional[str] = None  # e.g., DAG name, label ref

    def add_host(self, host: Host) -> None:
        self.hosts.append(host)

    def add_network(self, network: str) -> None:
        if network not in self.networks:
            self.networks.append(network)

    def get_all_ipv4(self) -> list[str]:
        """Get all IPv4 addresses including host IPs and network CIDRs."""
        ips = []
        for host in self.hosts:
            ips.extend(host.spec.addresses.ipv4)
        ips.extend(self.networks)
        return ips


class ResolvedGroup(BaseModel):
    """A group resolved to platform-specific representation."""
    name: str
    reference: str  # What policies should reference (e.g., group name)
    reference_type: str  # e.g., "address_group", "dynamic_address_group", "label"
    members: ResolvedMembers = Field(default_factory=ResolvedMembers)
    supporting_resources: str = ""  # Terraform for supporting resources


class ResolvedService(BaseModel):
    """A service resolved to platform-specific representation."""
    name: str
    protocols: list[ProtocolDef]
    applications: list[str] = Field(default_factory=list)  # For App-ID platforms
    service_reference: Optional[str] = None  # Service object name


class ResolvedPolicy(BaseModel):
    """A fully resolved policy ready for Terraform generation."""
    name: str
    description: str
    ticket: str
    source: ResolvedGroup
    destination: ResolvedGroup
    services: list[ResolvedService]
    action: Action
    logging: bool
