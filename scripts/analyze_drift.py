#!/usr/bin/env python3
"""
Analyze drift detection results.
"""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Analyze drift results")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--output", required=True)
    
    args = parser.parse_args()
    
    results_path = Path(args.results_dir)
    all_results = []
    
    # Load all result files
    for json_file in results_path.glob("*.json"):
        try:
            with open(json_file) as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_results.extend(data)
                else:
                    all_results.append(data)
        except Exception:
            pass
    
    # Analyze
    summary = {
        "total_workspaces": len(all_results),
        "has_drift": False,
        "critical_drift": False,
        "workspaces_with_drift": [],
        "workspaces_with_errors": [],
        "total_additions": 0,
        "total_changes": 0,
        "total_destructions": 0,
    }
    
    for result in all_results:
        if result.get("error"):
            summary["workspaces_with_errors"].append({
                "workspace": result.get("workspace"),
                "error": result.get("error"),
            })
            continue
        
        if result.get("has_drift"):
            summary["has_drift"] = True
            summary["workspaces_with_drift"].append({
                "workspace": result.get("workspace"),
                "additions": result.get("additions", 0),
                "changes": result.get("changes", 0),
                "destructions": result.get("destructions", 0),
            })
            
            summary["total_additions"] += result.get("additions", 0)
            summary["total_changes"] += result.get("changes", 0)
            summary["total_destructions"] += result.get("destructions", 0)
            
            # Critical if there are destructions
            if result.get("destructions", 0) > 0:
                summary["critical_drift"] = True
    
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Total workspaces: {summary['total_workspaces']}")
    print(f"Workspaces with drift: {len(summary['workspaces_with_drift'])}")
    print(f"Critical drift: {summary['critical_drift']}")


if __name__ == "__main__":
    main()
