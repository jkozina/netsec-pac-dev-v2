#!/usr/bin/env python3
"""
Send notifications for deployment status.
"""

import argparse
import json
import os

import requests


def send_slack_notification(
    webhook_url: str,
    status: str,
    commit: str,
    commit_url: str,
    workspaces: list[str],
):
    """Send Slack notification."""
    if status == "success":
        color = "good"
        emoji = "✅"
        title = "Network Policy Deployment Succeeded"
    elif status == "failure":
        color = "danger"
        emoji = "❌"
        title = "Network Policy Deployment Failed"
    else:
        color = "warning"
        emoji = "⚠️"
        title = f"Network Policy Deployment: {status}"
    
    workspace_list = "\n".join(f"• {ws}" for ws in workspaces[:10])
    if len(workspaces) > 10:
        workspace_list += f"\n• ... and {len(workspaces) - 10} more"
    
    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"{emoji} {title}",
                "fields": [
                    {
                        "title": "Commit",
                        "value": f"<{commit_url}|{commit[:8]}>",
                        "short": True,
                    },
                    {
                        "title": "Workspaces",
                        "value": str(len(workspaces)),
                        "short": True,
                    },
                ],
                "text": f"```\n{workspace_list}\n```",
                "footer": "Network Security Policy-as-Code",
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Slack notification timed out after 10 seconds") from None
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to send Slack notification: {e}") from e


def main():
    parser = argparse.ArgumentParser(description="Send deployment notifications")
    parser.add_argument("--status", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--commit-url", default="")
    parser.add_argument("--workspaces", default="[]")
    
    args = parser.parse_args()
    
    workspaces = json.loads(args.workspaces) if args.workspaces else []
    
    # Send Slack notification
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if slack_webhook:
        send_slack_notification(
            slack_webhook,
            args.status,
            args.commit,
            args.commit_url,
            workspaces,
        )
        print("Sent Slack notification")
    else:
        print("SLACK_WEBHOOK_URL not set, skipping notification")


if __name__ == "__main__":
    main()
