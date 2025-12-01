"""
Command-line interface for the policy-as-code framework.

Usage:
    python -m adapters.cli validate --registry registry/ --policies policies/
    python -m adapters.cli generate --registry registry/ --policies policies/ --output generated/terraform/
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .core.engine import AdapterEngine
from .core.registry import Registry
from .core.validator import Validator
from .core.models import Policy


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Network Security Policy-as-Code CLI."""
    pass


@cli.command()
@click.option(
    "--registry",
    "-r",
    default="registry/",
    help="Path to registry directory",
    type=click.Path(exists=True),
)
@click.option(
    "--policies",
    "-p",
    default="policies/",
    help="Path to policies directory or JSON list of policy files",
)
@click.option(
    "--schema-only",
    is_flag=True,
    help="Only validate schema, skip reference checking",
)
@click.option(
    "--check-references",
    is_flag=True,
    help="Check that all references exist in registry",
)
def validate(registry: str, policies: str, schema_only: bool, check_references: bool):
    """Validate registry objects and policies."""
    registry_path = Path(registry)
    schemas_path = Path("schemas/")

    # Initialize validator
    reg = Registry(registry_path) if check_references else None
    validator = Validator(schemas_path, registry=reg)

    all_errors: dict[str, list[str]] = {}

    # Validate registry
    click.echo("Validating registry...")
    registry_errors = validator.validate_registry(registry_path)
    all_errors.update(registry_errors)

    # Validate policies
    click.echo("Validating policies...")
    
    # Handle policies as either a path or JSON list
    if policies.startswith("["):
        # It's a JSON list
        policy_files = json.loads(policies)
    else:
        policies_path = Path(policies)
        if policies_path.is_file():
            policy_files = [policies_path]
        else:
            policy_files = list(policies_path.glob("**/*.yaml"))

    for policy_file in policy_files:
        policy_path = Path(policy_file)
        if policy_path.exists():
            errors = validator.validate_policy(policy_path)
            if errors:
                all_errors[str(policy_path)] = errors

    # Report results
    if all_errors:
        click.echo(click.style("\nValidation errors found:", fg="red"))
        for path, errors in all_errors.items():
            click.echo(f"\n{path}:")
            for error in errors:
                click.echo(f"  - {error}")
        sys.exit(1)
    else:
        click.echo(click.style("\nAll validations passed!", fg="green"))


@cli.command()
@click.option(
    "--registry",
    "-r",
    default="registry/",
    help="Path to registry directory",
    type=click.Path(exists=True),
)
@click.option(
    "--policies",
    "-p",
    required=True,
    help="Path to policies directory or JSON list of policy files",
)
@click.option(
    "--platform",
    "-t",
    multiple=True,
    help="Limit generation to specific platforms",
)
@click.option(
    "--output",
    "-o",
    default="generated/terraform/",
    help="Output directory for generated Terraform",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print output without writing files",
)
@click.option(
    "--workspace-manifest",
    help="Write affected workspaces to this JSON file",
)
def generate(
    registry: str,
    policies: str,
    platform: tuple,
    output: str,
    dry_run: bool,
    workspace_manifest: str,
):
    """Generate Terraform from network policies."""
    registry_path = Path(registry)
    output_path = Path(output)

    # Initialize engine
    engine = AdapterEngine(registry_path)

    # Parse policies input
    if policies.startswith("["):
        policy_files = json.loads(policies)
    else:
        policies_path = Path(policies)
        if policies_path.is_file():
            policy_files = [str(policies_path)]
        else:
            policy_files = [str(p) for p in policies_path.glob("**/*.yaml")]

    if not policy_files:
        click.echo("No policy files found")
        return

    click.echo(f"Processing {len(policy_files)} policy file(s)...")

    # Filter platforms if specified
    platforms = list(platform) if platform else None

    # Process all policies
    try:
        results = engine.process_policies(policy_files, platforms)
    except Exception as e:
        click.echo(click.style(f"Error processing policies: {e}", fg="red"))
        sys.exit(1)

    # Output results
    if dry_run:
        click.echo("\nDry run - would generate:")
        for policy_name, platforms_dict in results.items():
            for plat, scopes in platforms_dict.items():
                for scope, tf_content in scopes.items():
                    click.echo(f"\n--- {plat}/{scope}/{policy_name}.tf ---")
                    click.echo(tf_content[:500] + "..." if len(tf_content) > 500 else tf_content)
    else:
        # Write files
        affected = engine.write_terraform(results, output_path)
        
        click.echo(click.style(f"\nGenerated Terraform to {output_path}", fg="green"))
        for plat, workspaces in affected.items():
            click.echo(f"  {plat}: {len(workspaces)} workspace(s)")

        # Write workspace manifest if requested
        if workspace_manifest:
            all_workspaces = engine.get_workspace_manifest(affected)
            with open(workspace_manifest, "w") as f:
                json.dump(all_workspaces, f)
            click.echo(f"Wrote workspace manifest to {workspace_manifest}")


@cli.command()
@click.option(
    "--policies",
    "-p",
    required=True,
    help="JSON list of policy files to evaluate",
)
@click.option(
    "--rules",
    "-r",
    default="guardrails/rules.yaml",
    help="Path to guardrail rules file",
)
@click.option(
    "--registry",
    default="registry/",
    help="Path to registry directory",
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Output JSON file for results",
)
def guardrails(policies: str, rules: str, registry: str, output: str):
    """Evaluate policies against guardrails."""
    # This is a simplified implementation
    # In production, you'd have a full guardrails engine
    
    import yaml
    
    policy_files = json.loads(policies) if policies.startswith("[") else [policies]
    
    results = {
        "auto_approve": True,
        "require_review": False,
        "denied": False,
        "flagged_policies": [],
        "denied_policies": [],
    }
    
    # Load guardrail rules
    rules_path = Path(rules)
    if rules_path.exists():
        with open(rules_path) as f:
            guardrail_rules = yaml.safe_load(f)
    else:
        guardrail_rules = {"rules": []}
    
    reg = Registry(registry)
    
    for policy_file in policy_files:
        policy_path = Path(policy_file)
        if not policy_path.exists():
            continue
            
        policy = Policy.from_yaml(policy_path)
        
        # Check each guardrail rule
        for rule in guardrail_rules.get("rules", []):
            action = rule.get("action", "require-review")
            
            # Simplified rule evaluation
            # In production, implement proper condition parsing
            
            # Example: check for any-to-any
            if policy.spec.source.any and policy.spec.destination.any:
                if action == "deny":
                    results["denied"] = True
                    results["denied_policies"].append({
                        "name": policy.metadata.name,
                        "reason": "Any-to-any rules are prohibited",
                    })
                elif action == "require-review":
                    results["require_review"] = True
                    results["auto_approve"] = False
                    results["flagged_policies"].append({
                        "name": policy.metadata.name,
                        "reason": "Any-to-any rules require review",
                    })
    
    # Write results
    with open(output, "w") as f:
        json.dump(results, f, indent=2)
    
    click.echo(f"Guardrail evaluation complete: {output}")


if __name__ == "__main__":
    cli()
