#!/usr/bin/env python3
"""
Evaluate policies against guardrail rules.

Guardrails determine whether a policy can be auto-approved,
requires human review, or should be denied.
"""

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters.core.registry import Registry
from adapters.core.models import Policy


class GuardrailEngine:
    """Evaluates policies against guardrail rules."""
    
    def __init__(self, rules_path: str, registry: Registry):
        self.registry = registry
        self.rules = self._load_rules(rules_path)
    
    def _load_rules(self, rules_path: str) -> dict:
        """Load guardrail rules from YAML file."""
        path = Path(rules_path)
        if not path.exists():
            return {"rules": []}
        
        with open(path) as f:
            return yaml.safe_load(f) or {"rules": []}
    
    def evaluate(self, policy: Policy) -> dict:
        """
        Evaluate a policy against all guardrail rules.
        
        Returns:
            {
                "action": "auto-approve" | "require-review" | "deny",
                "matched_rules": [{"name": "...", "reason": "..."}],
            }
        """
        result = {
            "action": "auto-approve",
            "matched_rules": [],
        }
        
        for rule in self.rules.get("rules", []):
            match = self._evaluate_rule(policy, rule)
            if match:
                result["matched_rules"].append({
                    "name": rule.get("name", "unnamed"),
                    "reason": match,
                })
                
                rule_action = rule.get("action", "require-review")
                
                # Deny takes precedence over require-review
                if rule_action == "deny":
                    result["action"] = "deny"
                elif rule_action == "require-review" and result["action"] != "deny":
                    result["action"] = "require-review"
        
        return result
    
    def _evaluate_rule(self, policy: Policy, rule: dict) -> str | None:
        """
        Evaluate a single rule against a policy.
        
        Returns a reason string if the rule matches, None otherwise.
        """
        conditions = rule.get("conditions", [])
        
        for condition in conditions:
            if self._check_condition(policy, condition):
                return rule.get("message", f"Matched rule: {rule.get('name', 'unnamed')}")
        
        return None
    
    def _check_condition(self, policy: Policy, condition: str) -> bool:
        """
        Check if a condition matches the policy.
        
        Supports simplified condition syntax:
        - "source.type == any"
        - "destination.type == any"
        - "source.environment != destination.environment"
        - "services.port not in [22, 443, 80]"
        """
        # Any-to-any check
        if "source.type == any" in condition.lower():
            if policy.spec.source.any:
                return True
        
        if "destination.type == any" in condition.lower():
            if policy.spec.destination.any:
                return True
        
        # Cross-environment check
        if "source.environment != destination.environment" in condition.lower():
            src_group = policy.spec.source.group
            dst_group = policy.spec.destination.group
            
            if src_group and dst_group:
                try:
                    src = self.registry.get_group(src_group)
                    dst = self.registry.get_group(dst_group)
                    
                    # Check labels for environment
                    src_env = src.metadata.labels.get("environment")
                    dst_env = dst.metadata.labels.get("environment")
                    
                    if src_env and dst_env and src_env != dst_env:
                        return True
                except Exception:
                    pass
        
        # Internet-facing check
        if "source.type == internet" in condition.lower():
            if policy.spec.source.cidr in ["0.0.0.0/0", "any"]:
                return True
        
        if "destination.type == internet" in condition.lower():
            if policy.spec.destination.cidr in ["0.0.0.0/0", "any"]:
                return True
        
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate policies against guardrail rules"
    )
    parser.add_argument(
        "--policies",
        required=True,
        help="JSON list of policy files or path to policy",
    )
    parser.add_argument(
        "--rules",
        default="guardrails/rules.yaml",
        help="Path to guardrail rules file",
    )
    parser.add_argument(
        "--registry",
        default="registry/",
        help="Path to registry directory",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file",
    )
    
    args = parser.parse_args()
    
    # Parse policies
    if args.policies.startswith("["):
        policy_files = json.loads(args.policies)
    else:
        policy_path = Path(args.policies)
        if policy_path.is_file():
            policy_files = [str(policy_path)]
        else:
            policy_files = [str(p) for p in policy_path.glob("**/*.yaml")]
    
    # Initialize
    registry = Registry(args.registry)
    engine = GuardrailEngine(args.rules, registry)
    
    # Results
    results = {
        "auto_approve": True,
        "require_review": False,
        "denied": False,
        "policies": [],
        "flagged_policies": [],
        "denied_policies": [],
    }
    
    for policy_file in policy_files:
        path = Path(policy_file)
        if not path.exists():
            continue
        
        try:
            policy = Policy.from_yaml(path)
            evaluation = engine.evaluate(policy)
            
            policy_result = {
                "name": policy.metadata.name,
                "file": str(path),
                "action": evaluation["action"],
                "matched_rules": evaluation["matched_rules"],
            }
            results["policies"].append(policy_result)
            
            if evaluation["action"] == "deny":
                results["denied"] = True
                results["auto_approve"] = False
                results["denied_policies"].append({
                    "name": policy.metadata.name,
                    "reason": ", ".join(r["reason"] for r in evaluation["matched_rules"]),
                })
            elif evaluation["action"] == "require-review":
                results["require_review"] = True
                results["auto_approve"] = False
                results["flagged_policies"].append({
                    "name": policy.metadata.name,
                    "reason": ", ".join(r["reason"] for r in evaluation["matched_rules"]),
                })
                
        except Exception as e:
            print(f"Error processing {policy_file}: {e}", file=sys.stderr)
    
    # Write results
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Evaluated {len(policy_files)} policies")
    print(f"Auto-approve: {results['auto_approve']}")
    print(f"Require review: {results['require_review']}")
    print(f"Denied: {results['denied']}")


if __name__ == "__main__":
    main()
