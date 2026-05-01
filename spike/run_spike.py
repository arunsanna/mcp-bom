#!/usr/bin/env python3
"""
MCP-BOM Spike Runner
Runs the extractor on all available servers and produces a summary CSV + JSON.
"""

import json
import csv
import os
import subprocess
import sys
from pathlib import Path

# Servers we can analyze locally (official repo + cloned repos)
SERVERS = [
    # Official servers from modelcontextprotocol/servers
    {"id": "mcp-filesystem", "path": "/home/ubuntu/mcp-servers-official/src/filesystem", "tier": "official-high", "lang": "typescript", "description": "Filesystem read/write/search"},
    {"id": "mcp-memory", "path": "/home/ubuntu/mcp-servers-official/src/memory", "tier": "official-high", "lang": "typescript", "description": "Knowledge graph memory"},
    {"id": "mcp-sequential-thinking", "path": "/home/ubuntu/mcp-servers-official/src/sequentialthinking", "tier": "official-high", "lang": "typescript", "description": "Sequential thinking/reasoning"},
    {"id": "mcp-everything", "path": "/home/ubuntu/mcp-servers-official/src/everything", "tier": "official-high", "lang": "typescript", "description": "Test server exercising all MCP features"},
    {"id": "mcp-fetch", "path": "/home/ubuntu/mcp-servers-official/src/fetch", "tier": "official-high", "lang": "python", "description": "HTTP fetch/web scraping"},
    {"id": "mcp-git", "path": "/home/ubuntu/mcp-servers-official/src/git", "tier": "official-high", "lang": "python", "description": "Git repository operations"},
    {"id": "mcp-time", "path": "/home/ubuntu/mcp-servers-official/src/time", "tier": "official-low", "lang": "python", "description": "Time/timezone queries"},
]

# Community servers to clone
CLONE_SERVERS = [
    {"id": "mcp-shell-server", "repo": "https://github.com/tumf/mcp-shell-server", "tier": "community-low", "lang": "python", "description": "Shell command execution"},
    {"id": "mcp-server-docker", "repo": "https://github.com/ckreiling/mcp-server-docker", "tier": "community-medium", "lang": "python", "description": "Docker container management"},
    {"id": "mcp-server-mysql", "repo": "https://github.com/benborla/mcp-server-mysql", "tier": "community-medium", "lang": "python", "description": "MySQL database access"},
    {"id": "notion-mcp-server", "repo": "https://github.com/makenotion/notion-mcp-server", "tier": "enterprise-high", "lang": "typescript", "description": "Notion API integration"},
    {"id": "sentry-mcp", "repo": "https://github.com/getsentry/sentry-mcp", "tier": "enterprise-high", "lang": "typescript", "description": "Sentry error tracking"},
    {"id": "mcp-remote", "repo": "https://github.com/geelen/mcp-remote", "tier": "popular-high-cve", "lang": "typescript", "description": "Remote MCP proxy (CVE-2025-6514)"},
    {"id": "firecrawl-mcp", "repo": "https://github.com/mendableai/firecrawl-mcp-server", "tier": "popular-high", "lang": "typescript", "description": "Web crawling/scraping"},
    {"id": "mcp-server-kubernetes", "repo": "https://github.com/Flux159/mcp-server-kubernetes", "tier": "popular-high", "lang": "typescript", "description": "Kubernetes cluster management"},
    {"id": "chrome-devtools-mcp", "repo": "https://github.com/nichochar/chrome-devtools-mcp", "tier": "popular-medium", "lang": "typescript", "description": "Chrome DevTools automation"},
    {"id": "mcp-server-sqlite-py", "repo": "https://github.com/modelcontextprotocol/python-sdk", "tier": "official-high", "lang": "python", "description": "Python SDK examples"},
]

CLONE_DIR = "/home/ubuntu/mcp-spike-repos"


def clone_repos():
    """Clone community/enterprise repos for analysis."""
    os.makedirs(CLONE_DIR, exist_ok=True)
    for srv in CLONE_SERVERS:
        dest = os.path.join(CLONE_DIR, srv["id"])
        if not os.path.exists(dest):
            print(f"Cloning {srv['id']}...")
            subprocess.run(
                ["git", "clone", "--depth", "1", srv["repo"], dest],
                capture_output=True, timeout=60
            )
        srv["path"] = dest
    return CLONE_SERVERS


def run_extractor(server_path, server_id):
    """Run the extractor on a single server."""
    extractor_path = os.path.join(os.path.dirname(__file__), "extractor.py")
    try:
        result = subprocess.run(
            [sys.executable, extractor_path, server_path, server_id],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception as e:
        print(f"  Error scanning {server_id}: {e}")
    return None


def main():
    print("=" * 70)
    print("MCP-BOM SPIKE: Scanning servers against 9-category taxonomy")
    print("=" * 70)

    # Clone community repos
    print("\n[1/3] Cloning community repositories...")
    cloned = clone_repos()

    # Combine all servers
    all_servers = SERVERS + [s for s in cloned if os.path.exists(s.get("path", ""))]

    # Run extractor on each
    print(f"\n[2/3] Scanning {len(all_servers)} servers...")
    results = []
    for srv in all_servers:
        path = srv["path"]
        sid = srv["id"]
        if not os.path.exists(path):
            print(f"  SKIP {sid}: path not found")
            continue
        print(f"  Scanning {sid}...", end=" ")
        analysis = run_extractor(path, sid)
        if analysis:
            analysis["tier"] = srv.get("tier", "unknown")
            analysis["lang"] = srv.get("lang", "unknown")
            analysis["description"] = srv.get("description", "")
            results.append(analysis)
            cats = analysis["score"]["detected_categories"]
            score = analysis["score"]["attack_surface_score"]
            print(f"ASS={score:.1f}, categories={cats}")
        else:
            print("FAILED")

    # Save results
    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)

    # Full JSON
    json_path = os.path.join(output_dir, "spike_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    # Summary CSV
    csv_path = os.path.join(output_dir, "spike_summary.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "server_id", "tier", "lang", "description",
            "attack_surface_score", "breadth", "depth", "exposure",
            "num_categories", "detected_categories",
            "filesystem", "shell", "egress", "ingress", "secrets",
            "delegation", "impersonation", "data_sensitivity", "database"
        ])
        for r in results:
            s = r["score"]
            cv = r["capability_vector"]
            writer.writerow([
                r["server_id"], r["tier"], r["lang"], r["description"],
                s["attack_surface_score"], s["breadth"], s["depth"], s["exposure"],
                s["num_detected"], "|".join(s["detected_categories"]),
                cv.get("filesystem", False), cv.get("shell", False),
                cv.get("egress", False), cv.get("ingress", False),
                cv.get("secrets", False), cv.get("delegation", False),
                cv.get("impersonation", False), cv.get("data_sensitivity", False),
                cv.get("database", False),
            ])

    print(f"\n[3/3] Results saved:")
    print(f"  JSON: {json_path}")
    print(f"  CSV:  {csv_path}")
    print(f"  Total servers scanned: {len(results)}")

    # Quick hypothesis check
    print("\n" + "=" * 70)
    print("HYPOTHESIS VALIDATION (PRELIMINARY)")
    print("=" * 70)

    # H1: Execution-First Asymmetry
    shell_count = sum(1 for r in results if r["capability_vector"].get("shell", False))
    fs_count = sum(1 for r in results if r["capability_vector"].get("filesystem", False))
    print(f"\nH1 (Execution-First Asymmetry):")
    print(f"  Shell detected: {shell_count}/{len(results)} ({100*shell_count/len(results):.1f}%)")
    print(f"  Filesystem detected: {fs_count}/{len(results)} ({100*fs_count/len(results):.1f}%)")
    if shell_count > fs_count:
        print(f"  → SUPPORTED: Shell ({shell_count}) > Filesystem ({fs_count})")
    else:
        print(f"  → NOT SUPPORTED: Filesystem ({fs_count}) >= Shell ({shell_count})")

    # H3: Popularity Penalty
    high_tier = [r for r in results if "high" in r["tier"]]
    low_tier = [r for r in results if "low" in r["tier"] or "medium" in r["tier"]]
    if high_tier and low_tier:
        avg_high = sum(r["score"]["attack_surface_score"] for r in high_tier) / len(high_tier)
        avg_low = sum(r["score"]["attack_surface_score"] for r in low_tier) / len(low_tier)
        print(f"\nH3 (Popularity Penalty):")
        print(f"  High-tier avg ASS: {avg_high:.1f} (n={len(high_tier)})")
        print(f"  Low/Medium-tier avg ASS: {avg_low:.1f} (n={len(low_tier)})")
        if avg_high > avg_low:
            print(f"  → SUPPORTED: Popular servers score higher")
        else:
            print(f"  → NOT SUPPORTED: Low-tier scores higher")

    # Score distribution
    scores = sorted([r["score"]["attack_surface_score"] for r in results], reverse=True)
    print(f"\nScore Distribution:")
    print(f"  Max: {max(scores):.1f}")
    print(f"  Min: {min(scores):.1f}")
    print(f"  Mean: {sum(scores)/len(scores):.1f}")
    print(f"  Top 5: {[f'{s:.1f}' for s in scores[:5]]}")
    print(f"  Bottom 5: {[f'{s:.1f}' for s in scores[-5:]]}")


if __name__ == "__main__":
    main()
