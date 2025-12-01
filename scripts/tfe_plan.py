#!/usr/bin/env python3
"""
Terraform Enterprise plan helper.

Triggers speculative or real plans in TFE workspaces.
"""

import argparse
import json
import os
import time
from pathlib import Path

import requests


TFE_API = "https://app.terraform.io/api/v2"


def get_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/vnd.api+json",
    }


def get_workspace_id(org: str, workspace_name: str, token: str) -> str | None:
    """Look up workspace ID by name."""
    resp = requests.get(
        f"{TFE_API}/organizations/{org}/workspaces/{workspace_name}",
        headers=get_headers(token),
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()["data"]["id"]


def trigger_run(
    workspace_id: str,
    token: str,
    message: str = "Triggered by policy-as-code",
    speculative: bool = False,
) -> dict:
    """Trigger a Terraform run."""
    resp = requests.post(
        f"{TFE_API}/runs",
        headers=get_headers(token),
        json={
            "data": {
                "type": "runs",
                "attributes": {
                    "is-destroy": False,
                    "plan-only": speculative,
                    "message": message,
                },
                "relationships": {
                    "workspace": {
                        "data": {"type": "workspaces", "id": workspace_id}
                    }
                },
            }
        },
    )
    resp.raise_for_status()
    return resp.json()["data"]


def wait_for_plan(run_id: str, token: str, timeout: int = 300) -> dict:
    """Wait for plan to complete."""
    start = time.time()
    
    while time.time() - start < timeout:
        resp = requests.get(
            f"{TFE_API}/runs/{run_id}",
            headers=get_headers(token),
        )
        resp.raise_for_status()
        
        data = resp.json()["data"]
        status = data["attributes"]["status"]
        
        terminal_states = [
            "planned",
            "planned_and_finished",
            "applied",
            "errored",
            "canceled",
            "discarded",
        ]
        
        if status in terminal_states:
            return data
        
        time.sleep(10)
    
    raise TimeoutError(f"Plan {run_id} did not complete within {timeout}s")


def main():
    parser = argparse.ArgumentParser(description="Trigger TFE plans")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--generated-dir", required=True)
    parser.add_argument("--speculative", action="store_true")
    parser.add_argument("--output", required=True)
    
    args = parser.parse_args()
    
    token = os.environ.get("TFE_TOKEN")
    org = os.environ.get("TFE_ORG")
    
    if not token or not org:
        print("TFE_TOKEN and TFE_ORG environment variables required")
        # Write empty results
        with open(args.output, "w") as f:
            json.dump([], f)
        return
    
    results = []
    generated_path = Path(args.generated_dir)
    
    if not generated_path.exists():
        with open(args.output, "w") as f:
            json.dump([], f)
        return
    
    # Each subdirectory is a scope (workspace)
    for scope_dir in generated_path.iterdir():
        if not scope_dir.is_dir():
            continue
        
        workspace_name = f"netsec-{args.platform}-{scope_dir.name}"
        
        try:
            workspace_id = get_workspace_id(org, workspace_name, token)
            
            if not workspace_id:
                results.append({
                    "workspace": workspace_name,
                    "error": "Workspace not found",
                })
                continue
            
            run = trigger_run(
                workspace_id,
                token,
                message=f"{'Speculative plan' if args.speculative else 'Plan'} from policy-as-code",
                speculative=args.speculative,
            )
            
            plan_result = wait_for_plan(run["id"], token)
            
            results.append({
                "workspace": workspace_name,
                "run_id": run["id"],
                "status": plan_result["attributes"]["status"],
                "adds": plan_result["attributes"].get("resource-additions", 0),
                "changes": plan_result["attributes"].get("resource-changes", 0),
                "destroys": plan_result["attributes"].get("resource-destructions", 0),
            })
            
        except Exception as e:
            results.append({
                "workspace": workspace_name,
                "error": str(e),
            })
    
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Processed {len(results)} workspaces")


if __name__ == "__main__":
    main()
