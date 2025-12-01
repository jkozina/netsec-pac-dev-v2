#!/usr/bin/env python3
"""
Generate a GitHub PR comment summarizing validation and plan results.
"""

import argparse
import json
from pathlib import Path


def generate_comment(guardrail_results: dict, plan_results: list[dict]) -> str:
    """Generate markdown comment for PR."""
    lines = ["## 🔒 Network Policy Validation Results\n"]
    
    # Guardrail summary
    lines.append("### Guardrail Evaluation\n")
    
    if guardrail_results.get("denied"):
        lines.append("❌ **Denied**: Policy violates guardrails and cannot be merged\n")
        lines.append("\n**Denied policies:**\n")
        for policy in guardrail_results.get("denied_policies", []):
            lines.append(f"- `{policy['name']}`: {policy['reason']}\n")
    elif guardrail_results.get("require_review"):
        lines.append("⚠️ **Review Required**: Some policies require NetSec team approval\n")
        lines.append("\n**Flagged policies:**\n")
        for policy in guardrail_results.get("flagged_policies", []):
            lines.append(f"- `{policy['name']}`: {policy['reason']}\n")
    elif guardrail_results.get("auto_approve"):
        lines.append("✅ **Auto-approved**: All policies are within guardrails\n")
    else:
        lines.append("ℹ️ No policies evaluated\n")
    
    # Plan summary
    if plan_results:
        lines.append("\n### Terraform Plan Summary\n")
        lines.append("| Platform | Workspace | Status | +Add | ~Change | -Destroy |")
        lines.append("|----------|-----------|--------|------|---------|----------|")
        
        total_adds = 0
        total_changes = 0
        total_destroys = 0
        errors = []
        
        for result in plan_results:
            if "error" in result:
                lines.append(
                    f"| | {result.get('workspace', 'unknown')} | ❌ Error | - | - | - |"
                )
                errors.append(result)
            else:
                status = result.get("status", "unknown")
                status_icon = "✅" if status in ["planned", "planned_and_finished"] else "⚠️"
                
                adds = result.get("adds", 0)
                changes = result.get("changes", 0)
                destroys = result.get("destroys", 0)
                
                total_adds += adds
                total_changes += changes
                total_destroys += destroys
                
                # Extract platform from workspace name
                workspace = result.get("workspace", "unknown")
                parts = workspace.split("-")
                platform = parts[1] if len(parts) > 1 else ""
                
                lines.append(
                    f"| {platform} | {workspace} | {status_icon} {status} | "
                    f"{adds} | {changes} | {destroys} |"
                )
        
        lines.append(
            f"| **Total** | | | **{total_adds}** | **{total_changes}** | **{total_destroys}** |"
        )
        
        if errors:
            lines.append("\n#### Errors\n")
            for error in errors:
                lines.append(f"- `{error.get('workspace')}`: {error.get('error', 'Unknown error')}")
    else:
        lines.append("\n### Terraform Plan Summary\n")
        lines.append("ℹ️ No TFE plans available (TFE integration may not be configured)\n")
    
    # Footer
    lines.append("\n---")
    lines.append(
        "<details><summary>How to proceed</summary>\n\n"
        "- ✅ **Auto-approved**: Merge when ready\n"
        "- ⚠️ **Needs review**: Request review from @network-security-team\n"
        "- ❌ **Denied**: Address the guardrail violations before merging\n\n"
        "</details>"
    )
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate PR comment from validation results"
    )
    parser.add_argument(
        "--guardrails",
        required=True,
        help="Path to guardrail results JSON",
    )
    parser.add_argument(
        "--plan-results-dir",
        help="Directory containing plan result JSON files",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output markdown file",
    )
    
    args = parser.parse_args()
    
    # Load guardrail results
    with open(args.guardrails) as f:
        guardrail_results = json.load(f)
    
    # Load plan results
    plan_results = []
    if args.plan_results_dir:
        plan_dir = Path(args.plan_results_dir)
        if plan_dir.exists():
            for json_file in plan_dir.glob("*.json"):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            plan_results.extend(data)
                        else:
                            plan_results.append(data)
                except Exception:
                    pass
    
    # Generate comment
    comment = generate_comment(guardrail_results, plan_results)
    
    # Write output
    with open(args.output, "w") as f:
        f.write(comment)
    
    print(f"Generated PR comment: {args.output}")


if __name__ == "__main__":
    main()
