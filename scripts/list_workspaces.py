#!/usr/bin/env python3
"""
List TFE workspaces for a platform.
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


def list_workspaces(org: str, token: str, prefix: str = None) -> list[str]:
    """List all workspaces, optionally filtered by prefix."""
    workspaces = []
    url = f"{TFE_API}/organizations/{org}/workspaces"
    
    while url:
        resp = requests.get(url, headers=get_headers(token))
        resp.raise_for_status()
        
        data = resp.json()
        for ws in data["data"]:
            name = ws["attributes"]["name"]
            if prefix is None or name.startswith(prefix):
                workspaces.append(name)
        
        # Handle pagination
        url = data.get("links", {}).get("next")
    
    return workspaces


def main():
    parser = argparse.ArgumentParser(description="List TFE workspaces")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", required=True)
    
    args = parser.parse_args()
    
    token = os.environ.get("TFE_TOKEN")
    org = os.environ.get("TFE_ORG")
    
    if not token or not org:
        print("TFE_TOKEN and TFE_ORG environment variables required")
        with open(args.output, "w") as f:
            json.dump([], f)
        return
    
    prefix = f"netsec-{args.platform}-"
    workspaces = list_workspaces(org, token, prefix)
    
    with open(args.output, "w") as f:
        json.dump(workspaces, f, indent=2)
    
    print(f"Found {len(workspaces)} workspaces for platform {args.platform}")


if __name__ == "__main__":
    main()
