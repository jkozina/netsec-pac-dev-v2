"""
Tests for the core adapter functionality.
"""

import pytest
from pathlib import Path
import tempfile
import yaml

from adapters.core.models import Policy, Group, Host, Service
from adapters.core.registry import Registry
from adapters.core.engine import AdapterEngine


@pytest.fixture
def sample_registry(tmp_path):
    """Create a sample registry for testing."""
    # Create directory structure
    (tmp_path / "hosts" / "production").mkdir(parents=True)
    (tmp_path / "groups" / "application-groups").mkdir(parents=True)
    (tmp_path / "services" / "standard").mkdir(parents=True)
    
    # Create sample host
    host_data = {
        "apiVersion": "netsec/v1",
        "kind": "Host",
        "metadata": {"name": "test-host-01"},
        "spec": {
            "addresses": {"ipv4": ["10.0.0.1"]},
            "labels": {"tier": "web", "environment": "production"},
        },
    }
    with open(tmp_path / "hosts" / "production" / "test-host-01.yaml", "w") as f:
        yaml.dump(host_data, f)
    
    # Create sample group
    group_data = {
        "apiVersion": "netsec/v1",
        "kind": "Group",
        "metadata": {"name": "web-tier"},
        "spec": {
            "membership": {
                "dynamic": {"match-labels": {"tier": "web"}},
                "networks": ["10.0.0.0/24"],
            },
            "platform-mapping": {
                "paloalto": {
                    "strategy": "static-only",
                    "static": {"name": "grp-web-tier"},
                },
                "aws": {
                    "strategy": "cidr-only",
                },
            },
        },
    }
    with open(tmp_path / "groups" / "application-groups" / "web-tier.yaml", "w") as f:
        yaml.dump(group_data, f)
    
    # Create sample service
    service_data = {
        "apiVersion": "netsec/v1",
        "kind": "Service",
        "metadata": {"name": "https"},
        "spec": {
            "protocols": [{"protocol": "tcp", "port": 443}],
            "platform-mapping": {
                "paloalto": {
                    "use-app-id": True,
                    "applications": ["ssl"],
                    "service": "application-default",
                },
            },
        },
    }
    with open(tmp_path / "services" / "standard" / "https.yaml", "w") as f:
        yaml.dump(service_data, f)
    
    return tmp_path


@pytest.fixture
def sample_policy(tmp_path):
    """Create a sample policy for testing."""
    policy_data = {
        "apiVersion": "netsec/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "test-policy",
            "requestor": "test@example.com",
            "ticket": "TEST-123",
        },
        "spec": {
            "description": "Test policy",
            "source": {"group": "web-tier"},
            "destination": {"group": "web-tier"},
            "services": ["https"],
            "action": "allow",
            "logging": True,
            "targets": [
                {"platform": "paloalto", "scope": ["test-dg"]},
                {"platform": "aws", "scope": ["test-account"]},
            ],
        },
    }
    
    policy_path = tmp_path / "test-policy.yaml"
    with open(policy_path, "w") as f:
        yaml.dump(policy_data, f)
    
    return policy_path


class TestRegistry:
    def test_load_host(self, sample_registry):
        registry = Registry(sample_registry)
        host = registry.get_host("test-host-01")
        
        assert host.metadata.name == "test-host-01"
        assert "10.0.0.1" in host.spec.addresses.ipv4
    
    def test_load_group(self, sample_registry):
        registry = Registry(sample_registry)
        group = registry.get_group("web-tier")
        
        assert group.metadata.name == "web-tier"
        assert "10.0.0.0/24" in group.spec.membership.networks
    
    def test_load_service(self, sample_registry):
        registry = Registry(sample_registry)
        service = registry.get_service("https")
        
        assert service.metadata.name == "https"
        assert service.spec.protocols[0].port == 443
    
    def test_dynamic_membership(self, sample_registry):
        registry = Registry(sample_registry)
        group = registry.get_group("web-tier")
        
        # Host should match dynamic membership
        host = registry.get_host("test-host-01")
        assert group.matches_dynamically(host.spec.labels)
    
    def test_resolve_group_members(self, sample_registry):
        registry = Registry(sample_registry)
        group = registry.get_group("web-tier")
        
        members = registry.resolve_group_members(group)
        
        # Should include the host and the network
        assert len(members.hosts) == 1
        assert "10.0.0.0/24" in members.networks


class TestPolicy:
    def test_load_policy(self, sample_policy):
        policy = Policy.from_yaml(sample_policy)
        
        assert policy.metadata.name == "test-policy"
        assert policy.spec.source.group == "web-tier"
    
    def test_get_referenced_groups(self, sample_policy):
        policy = Policy.from_yaml(sample_policy)
        
        groups = policy.get_referenced_groups()
        assert "web-tier" in groups


class TestAdapterEngine:
    def test_process_policy(self, sample_registry, sample_policy):
        engine = AdapterEngine(sample_registry)
        policy = Policy.from_yaml(sample_policy)
        
        results = engine.process_policy(policy)
        
        # Should have results for both platforms
        assert "paloalto" in results
        assert "aws" in results
        
        # Palo Alto should have test-dg scope
        assert "test-dg" in results["paloalto"]
        
        # Generated TF should contain resource definitions
        tf_content = results["paloalto"]["test-dg"]
        assert "resource" in tf_content
        assert "test-policy" in tf_content
