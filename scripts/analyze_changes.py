#!/usr/bin/env python3
"""
Analyze changes to determine what policies need regeneration.

Handles both direct policy changes and indirect changes via registry updates.
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters.core.registry import Registry
from adapters.core.models import Policy


def find_affected_groups(changed_files: list[str], registry: Registry) -> set[str]:
    """
    Determine which groups are affected by the changed files.
    
    This includes groups whose dynamic membership would change due to
    host additions/modifications.
    """
    affected_groups = set()
    
    for f in changed_files:
        path = Path(f)
        
        # Direct group changes
        if f.startswith("registry/groups/"):
            affected_groups.add(path.stem)
            
        # Host changes - check if any group dynamically includes this host
        elif f.startswith("registry/hosts/"):
            if path.exists():
                try:
                    host = registry.load_host(f)
                    # Find groups that match this host's labels
                    matching_groups = registry.find_groups_matching_host(host)
                    for group in matching_groups:
                        affected_groups.add(group.metadata.name)
                except Exception:
                    # If we can't load the host, skip it
                    pass
    
    return affected_groups


def find_affected_services(changed_files: list[str]) -> set[str]:
    """Find services that were directly modified."""
    affected_services = set()
    
    for f in changed_files:
        if f.startswith("registry/services/"):
            path = Path(f)
            affected_services.add(path.stem)
    
    return affected_services


def find_affected_policies(
    changed_files: list[str],
    registry: Registry,
    policies_path: Path,
) -> list[str]:
    """
    Find all policies that need regeneration.
    
    This includes:
    - Directly modified policies
    - Policies referencing modified groups
    - Policies referencing groups affected by host changes
    - Policies using modified services
    """
    affected_policies = set()
    
    # Direct policy changes
    for f in changed_files:
        if f.startswith("policies/") and f.endswith(".yaml"):
            affected_policies.add(f)
    
    # Find affected groups (including dynamic membership changes)
    affected_groups = find_affected_groups(changed_files, registry)
    
    # Find affected services
    affected_services = find_affected_services(changed_files)
    
    # If nothing in registry changed, return just direct policy changes
    if not affected_groups and not affected_services:
        return list(affected_policies)
    
    # Scan all policies for references to affected objects
    for policy_file in policies_path.glob("**/*.yaml"):
        try:
            policy = Policy.from_yaml(policy_file)
            
            # Check group references
            policy_groups = policy.get_referenced_groups()
            if policy_groups & affected_groups:
                affected_policies.add(str(policy_file))
                continue
            
            # Check service references
            policy_services = policy.get_referenced_services()
            if policy_services & affected_services:
                affected_policies.add(str(policy_file))
                continue
                
        except Exception:
            # Skip files that can't be parsed
            pass
    
    return list(affected_policies)


def analyze_changes(
    changed_files: list[str],
    registry_path: str,
    policies_path: str,
) -> dict:
    """
    Main analysis function.
    
    Returns a dict with:
    - direct_policy_changes: Policies that were directly modified
    - registry_changes: Registry files that were modified
    - affected_groups: Groups affected by registry changes
    - affected_policies: All policies that need regeneration
    - regeneration_needed: Whether any regeneration is needed
    """
    registry = Registry(registry_path)
    policies_dir = Path(policies_path)
    
    result = {
        "direct_policy_changes": [],
        "registry_changes": [],
        "affected_groups": [],
        "affected_services": [],
        "affected_policies": [],
        "regeneration_needed": False,
    }
    
    # Categorize changes
    for f in changed_files:
        if f.startswith("policies/"):
            result["direct_policy_changes"].append(f)
        elif f.startswith("registry/"):
            result["registry_changes"].append(f)
    
    # Find affected groups
    affected_groups = find_affected_groups(changed_files, registry)
    result["affected_groups"] = list(affected_groups)
    
    # Find affected services
    affected_services = find_affected_services(changed_files)
    result["affected_services"] = list(affected_services)
    
    # Find all affected policies
    affected_policies = find_affected_policies(changed_files, registry, policies_dir)
    result["affected_policies"] = affected_policies
    result["regeneration_needed"] = len(affected_policies) > 0
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Analyze changes to determine what policies need regeneration"
    )
    parser.add_argument(
        "--changed-files",
        required=True,
        help="Space-separated list of changed files",
    )
    parser.add_argument(
        "--registry",
        default="registry/",
        help="Path to registry directory",
    )
    parser.add_argument(
        "--policies",
        default="policies/",
        help="Path to policies directory",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file",
    )
    
    args = parser.parse_args()
    
    # Parse changed files
    changed_files = [f.strip() for f in args.changed_files.split() if f.strip()]
    
    # Run analysis
    result = analyze_changes(changed_files, args.registry, args.policies)
    
    # Write output
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    
    # Print summary
    print(f"Direct policy changes: {len(result['direct_policy_changes'])}")
    print(f"Registry changes: {len(result['registry_changes'])}")
    print(f"Affected groups: {result['affected_groups']}")
    print(f"Affected services: {result['affected_services']}")
    print(f"Policies to regenerate: {len(result['affected_policies'])}")
    print(f"Regeneration needed: {result['regeneration_needed']}")


if __name__ == "__main__":
    main()
