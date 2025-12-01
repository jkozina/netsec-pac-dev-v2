#!/usr/bin/env python3
"""
Wait for TFE run to complete.
"""

import argparse
import os
import sys
import time

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


def get_latest_run(workspace_id: str, token: str) -> dict | None:
    """Get the latest run for a workspace."""
    resp = requests.get(
        f"{TFE_API}/workspaces/{workspace_id}/runs",
        headers=get_headers(token),
        params={"page[size]": 1},
    )
    resp.raise_for_status()
    runs = resp.json()["data"]
    return runs[0] if runs else None


def wait_for_run(run_id: str, token: str, timeout: int = 600) -> dict:
    """Wait for run to complete."""
    start = time.time()
    
    while time.time() - start < timeout:
        resp = requests.get(
            f"{TFE_API}/runs/{run_id}",
            headers=get_headers(token),
        )
        resp.raise_for_status()
        
        data = resp.json()["data"]
        status = data["attributes"]["status"]
        
        print(f"Run {run_id} status: {status}")
        
        terminal_states = [
            "applied",
            "planned_and_finished",
            "errored",
            "canceled",
            "discarded",
            "force_canceled",
        ]
        
        if status in terminal_states:
            return data
        
        time.sleep(15)
    
    raise TimeoutError(f"Run {run_id} did not complete within {timeout}s")


def main():
    parser = argparse.ArgumentParser(description="Wait for TFE run")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--timeout", type=int, default=600)
    
    args = parser.parse_args()
    
    token = os.environ.get("TFE_TOKEN")
    org = os.environ.get("TFE_ORG")
    
    if not token or not org:
        print("TFE_TOKEN and TFE_ORG environment variables required")
        sys.exit(1)
    
    workspace_id = get_workspace_id(org, args.workspace, token)
    
    if not workspace_id:
        print(f"Workspace not found: {args.workspace}")
        sys.exit(1)
    
    run = get_latest_run(workspace_id, token)
    
    if not run:
        print(f"No runs found for workspace: {args.workspace}")
        sys.exit(1)
    
    try:
        result = wait_for_run(run["id"], token, args.timeout)
        status = result["attributes"]["status"]
        
        if status in ["applied", "planned_and_finished"]:
            print(f"Run completed successfully: {status}")
            sys.exit(0)
        else:
            print(f"Run ended with status: {status}")
            sys.exit(1)
            
    except TimeoutError as e:
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
