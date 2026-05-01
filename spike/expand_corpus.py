#!/usr/bin/env python3
"""
Expand the spike corpus by cloning additional MCP servers.
Targets 30+ servers across popularity tiers, languages, and registries.
"""

import subprocess
import os
import json

CLONE_DIR = "/home/ubuntu/mcp-spike-repos"
os.makedirs(CLONE_DIR, exist_ok=True)

# Additional servers to clone (beyond what we already have)
NEW_SERVERS = [
    # Enterprise / High-popularity
    {"id": "hubspot-mcp", "repo": "https://github.com/HubSpot/hubspot-mcp-server", "lang": "typescript", "tier": "enterprise-high", "desc": "HubSpot CRM integration"},
    {"id": "stripe-mcp", "repo": "https://github.com/stripe/agent-toolkit", "lang": "typescript", "tier": "enterprise-high", "desc": "Stripe payment processing"},
    {"id": "cloudflare-mcp", "repo": "https://github.com/cloudflare/mcp-server-cloudflare", "lang": "typescript", "tier": "enterprise-high", "desc": "Cloudflare infrastructure"},
    {"id": "supabase-mcp", "repo": "https://github.com/supabase-community/supabase-mcp", "lang": "typescript", "tier": "enterprise-high", "desc": "Supabase database/auth"},
    {"id": "linear-mcp", "repo": "https://github.com/jerhadf/linear-mcp-server", "lang": "typescript", "tier": "popular-high", "desc": "Linear issue tracking"},

    # Database-focused (for H11 God Mode Default)
    {"id": "postgres-mcp-py", "repo": "https://github.com/crystaldb/postgres-mcp", "lang": "python", "tier": "community-medium", "desc": "PostgreSQL MCP server"},
    {"id": "sqlite-mcp-py", "repo": "https://github.com/nichochar/sqlite-mcp", "lang": "python", "tier": "community-medium", "desc": "SQLite MCP server"},
    {"id": "mongo-mcp", "repo": "https://github.com/kiliczsh/mongo-mcp", "lang": "typescript", "tier": "community-medium", "desc": "MongoDB MCP server"},

    # Shell/Exec focused (for H6 Co-Location)
    {"id": "mcp-server-commands", "repo": "https://github.com/nichochar/mcp-server-commands", "lang": "python", "tier": "community-low", "desc": "Command execution server"},
    {"id": "terminal-mcp", "repo": "https://github.com/wonderwhy-er/ClaudeDesktopCommandExecutionMCP", "lang": "typescript", "tier": "community-low", "desc": "Terminal/command execution"},

    # Communication/Impersonation (for H10)
    {"id": "slack-mcp", "repo": "https://github.com/modelcontextprotocol/servers", "subpath": "src/slack", "lang": "typescript", "tier": "official-high", "desc": "Slack messaging"},
    {"id": "gmail-mcp", "repo": "https://github.com/nichochar/gmail-mcp", "lang": "python", "tier": "community-medium", "desc": "Gmail email sending"},

    # Web/API focused
    {"id": "brave-search-mcp", "repo": "https://github.com/nichochar/brave-search-mcp", "lang": "typescript", "tier": "popular-medium", "desc": "Brave search API"},
    {"id": "playwright-mcp", "repo": "https://github.com/nichochar/playwright-mcp", "lang": "typescript", "tier": "popular-high", "desc": "Browser automation"},
    {"id": "puppeteer-mcp", "repo": "https://github.com/nichochar/puppeteer-mcp", "lang": "typescript", "tier": "popular-high", "desc": "Puppeteer browser automation"},

    # Go servers (for H13 Safe Language Fallacy)
    {"id": "go-mcp-server", "repo": "https://github.com/mark3labs/mcp-go", "lang": "go", "tier": "community-medium", "desc": "Go MCP SDK/server"},
]

def clone_server(srv):
    dest = os.path.join(CLONE_DIR, srv["id"])
    if os.path.exists(dest):
        print(f"  EXISTS: {srv['id']}")
        return True
    print(f"  CLONING: {srv['id']} from {srv['repo']}...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", srv["repo"], dest],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            print(f"    OK")
            return True
        else:
            print(f"    FAILED: {result.stderr[:100]}")
            return False
    except Exception as e:
        print(f"    ERROR: {e}")
        return False

if __name__ == "__main__":
    print(f"Expanding corpus: {len(NEW_SERVERS)} additional servers")
    success = 0
    for srv in NEW_SERVERS:
        if clone_server(srv):
            success += 1
    print(f"\nCloned {success}/{len(NEW_SERVERS)} servers")

    # Save the expanded manifest
    manifest = []
    for srv in NEW_SERVERS:
        dest = os.path.join(CLONE_DIR, srv["id"])
        if os.path.exists(dest):
            entry = dict(srv)
            entry["path"] = dest
            manifest.append(entry)

    manifest_path = os.path.join(CLONE_DIR, "expanded_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest saved: {manifest_path}")
