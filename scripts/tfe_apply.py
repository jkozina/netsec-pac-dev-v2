#!/usr/bin/env python3
"""
Terraform Enterprise apply helper.

Triggers applies in TFE workspaces.
"""

import argparse
import os

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
    message: str = "Apply from policy-as-code",
    auto_apply: bool = False,
) -> dict:
    """Trigger a Terraform run with optional auto-apply."""
    resp = requests.post(
        f"{TFE_API}/runs",
        headers=get_headers(token),
        json={
            "data": {
                "type": "runs",
                "attributes": {
                    "is-destroy": False,
                    "auto-apply": auto_apply,
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


def main():
    parser = argparse.ArgumentParser(description="Trigger TFE apply")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--message", default="Apply from policy-as-code")
    parser.add_argument("--auto-apply", action="store_true")
    
    args = parser.parse_args()
    
    token = os.environ.get("TFE_TOKEN")
    org = os.environ.get("TFE_ORG")
    
    if not token or not org:
        print("TFE_TOKEN and TFE_ORG environment variables required")
        return
    
    workspace_id = get_workspace_id(org, args.workspace, token)
    
    if not workspace_id:
        print(f"Workspace not found: {args.workspace}")
        return
    
    run = trigger_run(
        workspace_id,
        token,
        message=args.message,
        auto_apply=args.auto_apply,
    )
    
    print(f"Triggered run {run['id']} for workspace {args.workspace}")


if __name__ == "__main__":
    main()
