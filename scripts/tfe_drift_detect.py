#!/usr/bin/env python3
"""
Detect drift in TFE workspaces.
"""

import argparse
import json
import os

import requests


TFE_API = "https://app.terraform.io/api/v2"


def get_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/vnd.api+json",
    }


def check_workspace_drift(workspace_name: str, org: str, token: str) -> dict:
    """Check if a workspace has drift."""
    # Get workspace
    resp = requests.get(
        f"{TFE_API}/organizations/{org}/workspaces/{workspace_name}",
        headers=get_headers(token),
    )
    
    if resp.status_code == 404:
        return {"workspace": workspace_name, "error": "Not found"}
    
    resp.raise_for_status()
    workspace = resp.json()["data"]
    workspace_id = workspace["id"]
    
    # Trigger a plan-only run to detect drift
    run_resp = requests.post(
        f"{TFE_API}/runs",
        headers=get_headers(token),
        json={
            "data": {
                "type": "runs",
                "attributes": {
                    "plan-only": True,
                    "refresh-only": True,
                    "message": "Drift detection",
                },
                "relationships": {
                    "workspace": {
                        "data": {"type": "workspaces", "id": workspace_id}
                    }
                },
            }
        },
    )
    run_resp.raise_for_status()
    run = run_resp.json()["data"]
    
    # Wait for plan
    import time
    for _ in range(60):
        status_resp = requests.get(
            f"{TFE_API}/runs/{run['id']}",
            headers=get_headers(token),
        )
        status_resp.raise_for_status()
        run_data = status_resp.json()["data"]
        status = run_data["attributes"]["status"]
        
        if status in ["planned", "planned_and_finished", "errored"]:
            break
        time.sleep(5)
    
    # Check for changes
    attrs = run_data["attributes"]
    has_changes = (
        attrs.get("resource-additions", 0) > 0 or
        attrs.get("resource-changes", 0) > 0 or
        attrs.get("resource-destructions", 0) > 0
    )
    
    return {
        "workspace": workspace_name,
        "has_drift": has_changes,
        "additions": attrs.get("resource-additions", 0),
        "changes": attrs.get("resource-changes", 0),
        "destructions": attrs.get("resource-destructions", 0),
        "run_id": run["id"],
    }


def main():
    parser = argparse.ArgumentParser(description="Detect TFE drift")
    parser.add_argument("--workspaces", required=True, help="JSON list of workspaces")
    parser.add_argument("--output", required=True)
    
    args = parser.parse_args()
    
    token = os.environ.get("TFE_TOKEN")
    org = os.environ.get("TFE_ORG")
    
    if not token or not org:
        print("TFE_TOKEN and TFE_ORG environment variables required")
        with open(args.output, "w") as f:
            json.dump([], f)
        return
    
    workspaces = json.loads(args.workspaces)
    results = []
    
    for workspace in workspaces:
        try:
            result = check_workspace_drift(workspace, org, token)
            results.append(result)
        except Exception as e:
            results.append({"workspace": workspace, "error": str(e)})
    
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    
    drift_count = sum(1 for r in results if r.get("has_drift"))
    print(f"Checked {len(results)} workspaces, {drift_count} with drift")


if __name__ == "__main__":
    main()
