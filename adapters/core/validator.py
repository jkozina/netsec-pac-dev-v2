"""
Validation module for policies and registry objects.

Provides schema validation and reference checking.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .models import Policy, Host, Group, Service
from .registry import Registry


class ValidationError(Exception):
    """Raised when validation fails."""
    
    def __init__(self, message: str, errors: list[str] = None):
        super().__init__(message)
        self.errors = errors or []


class Validator:
    """Validates policies and registry objects against schemas and business rules."""

    def __init__(self, schemas_path: str | Path, registry: Registry = None):
        self.schemas_path = Path(schemas_path)
        self.registry = registry
        self._schemas: dict[str, dict] = {}
        self._load_schemas()

    def _load_schemas(self) -> None:
        """Load all JSON schemas from the schemas directory."""
        schema_files = {
            "policy": "policy.schema.json",
            "host": "host.schema.json",
            "group": "group.schema.json",
            "service": "service.schema.json",
        }

        for name, filename in schema_files.items():
            schema_path = self.schemas_path / filename
            if schema_path.exists():
                with open(schema_path) as f:
                    self._schemas[name] = json.load(f)

    def validate_yaml_file(self, path: Path, schema_name: str) -> list[str]:
        """
        Validate a YAML file against its schema.
        
        Returns a list of validation errors (empty if valid).
        """
        errors = []

        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [f"YAML parse error: {e}"]

        if schema_name not in self._schemas:
            return [f"Unknown schema: {schema_name}"]

        schema = self._schemas[schema_name]

        try:
            jsonschema.validate(data, schema)
        except jsonschema.ValidationError as e:
            errors.append(f"Schema validation error at {e.json_path}: {e.message}")
        except jsonschema.SchemaError as e:
            errors.append(f"Schema error: {e.message}")

        return errors

    def validate_policy(self, policy_path: Path) -> list[str]:
        """Validate a policy file."""
        errors = self.validate_yaml_file(policy_path, "policy")
        
        if errors:
            return errors

        # Load and validate references if registry is available
        if self.registry:
            try:
                policy = Policy.from_yaml(policy_path)
                ref_errors = self.registry.validate_policy_references(policy)
                errors.extend(ref_errors)
            except Exception as e:
                errors.append(f"Failed to load policy: {e}")

        return errors

    def validate_host(self, host_path: Path) -> list[str]:
        """Validate a host file."""
        return self.validate_yaml_file(host_path, "host")

    def validate_group(self, group_path: Path) -> list[str]:
        """Validate a group file."""
        errors = self.validate_yaml_file(group_path, "group")

        if errors:
            return errors

        # Validate group references if registry is available
        if self.registry:
            try:
                group = Group.from_yaml(group_path)
                
                # Check static host references
                for host_ref in group.spec.membership.static:
                    try:
                        self.registry.get_host(host_ref)
                    except Exception:
                        errors.append(f"Referenced host not found: {host_ref}")

                # Check nested group references
                for nested_ref in group.spec.membership.groups:
                    try:
                        self.registry.get_group(nested_ref)
                    except Exception:
                        errors.append(f"Referenced group not found: {nested_ref}")

            except Exception as e:
                errors.append(f"Failed to load group: {e}")

        return errors

    def validate_service(self, service_path: Path) -> list[str]:
        """Validate a service file."""
        return self.validate_yaml_file(service_path, "service")

    def validate_registry(self, registry_path: Path) -> dict[str, list[str]]:
        """
        Validate all files in the registry.
        
        Returns a dict mapping file paths to their validation errors.
        """
        all_errors: dict[str, list[str]] = {}

        # Validate hosts
        hosts_path = registry_path / "hosts"
        if hosts_path.exists():
            for yaml_file in hosts_path.glob("**/*.yaml"):
                errors = self.validate_host(yaml_file)
                if errors:
                    all_errors[str(yaml_file)] = errors

        # Validate groups
        groups_path = registry_path / "groups"
        if groups_path.exists():
            for yaml_file in groups_path.glob("**/*.yaml"):
                errors = self.validate_group(yaml_file)
                if errors:
                    all_errors[str(yaml_file)] = errors

        # Validate services
        services_path = registry_path / "services"
        if services_path.exists():
            for yaml_file in services_path.glob("**/*.yaml"):
                errors = self.validate_service(yaml_file)
                if errors:
                    all_errors[str(yaml_file)] = errors

        return all_errors

    def validate_policies(self, policies_path: Path) -> dict[str, list[str]]:
        """
        Validate all policy files.
        
        Returns a dict mapping file paths to their validation errors.
        """
        all_errors: dict[str, list[str]] = {}

        for yaml_file in policies_path.glob("**/*.yaml"):
            errors = self.validate_policy(yaml_file)
            if errors:
                all_errors[str(yaml_file)] = errors

        return all_errors
