#!/usr/bin/env python3
"""
MCP-BOM Hypothesis Tooling
Additional detectors for H6, H7, H8, H10, H12, H13, H14.
"""

import json
import re
import os
import subprocess
from pathlib import Path
from collections import Counter
from difflib import SequenceMatcher
import numpy as np

RESULTS_DIR = Path(__file__).parent / "results"

# ── H7: Typosquat / Lookalike Detector ──────────────────────────────────

# Known canonical MCP server names (official or well-established)
CANONICAL_NAMES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
    "mcp-server-fetch", "mcp-server-git", "mcp-server-time",
    "mcp-server-sqlite", "mcp-server-postgres", "mcp-server-sentry",
    "mcp-server-github", "mcp-server-slack", "mcp-server-brave-search",
    "mcp-server-gdrive", "mcp-server-docker", "mcp-server-kubernetes",
    "@notionhq/notion-mcp-server", "@sentry/mcp-server",
    "@heroku/mcp-server", "@railway/mcp-server",
]


def detect_lookalikes(corpus):
    """Find packages that are suspiciously similar to canonical names."""
    lookalikes = []
    canonical_basenames = {}
    for name in CANONICAL_NAMES:
        base = name.split("/")[-1].lower().replace("-", "").replace("_", "")
        canonical_basenames[base] = name

    for server in corpus:
        name = server["name"]
        base = name.split("/")[-1].lower().replace("-", "").replace("_", "")

        # Skip if it IS a canonical name
        if name in CANONICAL_NAMES:
            continue

        # Check similarity to each canonical name
        for canon_base, canon_full in canonical_basenames.items():
            ratio = SequenceMatcher(None, base, canon_base).ratio()
            if 0.75 <= ratio < 1.0 and base != canon_base:
                lookalikes.append({
                    "suspect": name,
                    "resembles": canon_full,
                    "similarity": round(ratio, 3),
                    "registry": server.get("registry", "unknown"),
                })
    return lookalikes


# ── H8: Registry Governance Analysis ────────────────────────────────────

def analyze_registry_governance(corpus):
    """Compare score distributions across registries."""
    by_registry = {}
    for s in corpus:
        reg = s.get("registry", "unknown")
        if reg not in by_registry:
            by_registry[reg] = []
        by_registry[reg].append(s)
    return by_registry


# ── H12: SAST Integration (Semgrep) ────────────────────────────────────

def run_semgrep_on_dir(dirpath):
    """Run Semgrep on a directory and count findings."""
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(dirpath)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode in [0, 1]:  # 0=no findings, 1=findings found
            data = json.loads(result.stdout)
            findings = data.get("results", [])
            # Count by severity
            severities = Counter(f.get("extra", {}).get("severity", "unknown") for f in findings)
            return {
                "total_findings": len(findings),
                "by_severity": dict(severities),
                "cwe_ids": list(set(
                    cwe.get("cwe_id", "")
                    for f in findings
                    for cwe in f.get("extra", {}).get("metadata", {}).get("cwe", [])
                    if isinstance(cwe, dict)
                )),
            }
    except FileNotFoundError:
        return {"error": "semgrep not installed"}
    except Exception as e:
        return {"error": str(e)}
    return {"total_findings": 0, "by_severity": {}, "cwe_ids": []}


# ── H14: Schema vs Implementation Drift ─────────────────────────────────

def detect_schema_drift(dirpath):
    """Compare capabilities declared in tool schemas vs detected in implementation."""
    schema_capabilities = set()
    impl_capabilities = set()

    dirpath = Path(dirpath)
    for ext in ["*.py", "*.ts", "*.js"]:
        for fpath in dirpath.rglob(ext):
            fstr = str(fpath)
            if "test" in fstr.lower() or "node_modules" in fstr or "__pycache__" in fstr:
                continue
            try:
                content = open(fpath, 'r', errors='ignore').read()
            except:
                continue

            # Schema-declared tools (what the LLM sees)
            # Look for tool registration patterns
            tool_names = re.findall(
                r'(?:name|tool_name|toolName)\s*[:=]\s*["\']([^"\']+)', content
            )
            tool_descs = re.findall(
                r'(?:description|desc)\s*[:=]\s*["\']([^"\']{10,})', content
            )

            for desc in tool_descs:
                desc_lower = desc.lower()
                if any(w in desc_lower for w in ["file", "read", "write", "directory"]):
                    schema_capabilities.add("filesystem")
                if any(w in desc_lower for w in ["execute", "run", "command", "shell"]):
                    schema_capabilities.add("shell")
                if any(w in desc_lower for w in ["fetch", "http", "request", "url", "api"]):
                    schema_capabilities.add("egress")
                if any(w in desc_lower for w in ["database", "query", "sql", "table"]):
                    schema_capabilities.add("database")
                if any(w in desc_lower for w in ["send", "email", "message", "post", "slack"]):
                    schema_capabilities.add("impersonation")

            # Implementation capabilities (what the code actually does)
            # Import-based detection
            if re.search(r'\bsubprocess\b|\bchild_process\b|\bos\.system\b|\bexec\b', content):
                impl_capabilities.add("shell")
            if re.search(r'\bfs\b|\bopen\s*\(|\bpathlib\b|\bos\.path\b', content):
                impl_capabilities.add("filesystem")
            if re.search(r'\brequests\b|\bfetch\b|\baxios\b|\bhttpx\b|\baiohttp\b', content):
                impl_capabilities.add("egress")
            if re.search(r'\bsqlite3\b|\bpsycopg\b|\bsqlalchemy\b|\bpg\b|\bmysql\b|\bmongoose\b', content):
                impl_capabilities.add("database")
            if re.search(r'\bsmtplib\b|\bnodemailer\b|\bslack_sdk\b|\b@slack\b', content):
                impl_capabilities.add("impersonation")
            if re.search(r'\bos\.environ\b|\bprocess\.env\b|\bdotenv\b', content):
                impl_capabilities.add("secrets")

    # Hidden capabilities = in implementation but NOT in schema
    hidden = impl_capabilities - schema_capabilities
    declared_only = schema_capabilities - impl_capabilities

    return {
        "schema_declared": sorted(schema_capabilities),
        "impl_detected": sorted(impl_capabilities),
        "hidden_capabilities": sorted(hidden),
        "declared_but_not_impl": sorted(declared_only),
        "has_drift": len(hidden) > 0,
        "drift_count": len(hidden),
    }


# ── H10: Approval Gate Detector (Enhanced) ──────────────────────────────

def detect_approval_patterns(dirpath):
    """Enhanced detection of approval/confirmation gates in impersonation servers."""
    patterns_found = {
        "has_user_confirmation": False,
        "has_dry_run": False,
        "has_approval_workflow": False,
        "confirmation_patterns": [],
    }

    dirpath = Path(dirpath)
    for ext in ["*.py", "*.ts", "*.js"]:
        for fpath in dirpath.rglob(ext):
            fstr = str(fpath)
            if "test" in fstr.lower() or "node_modules" in fstr:
                continue
            try:
                content = open(fpath, 'r', errors='ignore').read()
            except:
                continue

            # User confirmation patterns
            if re.search(r'\bconfirm\b.*\b(?:send|post|publish|email|message)\b', content, re.IGNORECASE):
                patterns_found["has_user_confirmation"] = True
                patterns_found["confirmation_patterns"].append("confirm_before_action")
            if re.search(r'\binput\s*\([^)]*(?:confirm|proceed|approve)', content, re.IGNORECASE):
                patterns_found["has_user_confirmation"] = True
                patterns_found["confirmation_patterns"].append("input_prompt")

            # Dry-run patterns
            if re.search(r'\bdry[_-]?run\b', content, re.IGNORECASE):
                patterns_found["has_dry_run"] = True
                patterns_found["confirmation_patterns"].append("dry_run")

            # Approval workflow
            if re.search(r'\bapproval\b|\bapprove\b|\bpending\b.*\breview\b', content, re.IGNORECASE):
                patterns_found["has_approval_workflow"] = True
                patterns_found["confirmation_patterns"].append("approval_workflow")

    patterns_found["has_any_gate"] = any([
        patterns_found["has_user_confirmation"],
        patterns_found["has_dry_run"],
        patterns_found["has_approval_workflow"],
    ])
    return patterns_found


if __name__ == "__main__":
    # Quick test: run lookalike detection on scraped corpus
    corpus_path = RESULTS_DIR / "scraped_corpus.json"
    if corpus_path.exists():
        with open(corpus_path) as f:
            corpus = json.load(f)

        print("=" * 70)
        print("H7: LOOKALIKE DETECTION")
        print("=" * 70)
        lookalikes = detect_lookalikes(corpus)
        print(f"Found {len(lookalikes)} potential lookalikes:")
        for la in sorted(lookalikes, key=lambda x: -x["similarity"])[:20]:
            print(f"  {la['suspect']:50s} resembles {la['resembles']:40s} sim={la['similarity']}")

        print(f"\n{'='*70}")
        print("H8: REGISTRY DISTRIBUTION")
        print("=" * 70)
        by_reg = analyze_registry_governance(corpus)
        for reg, servers in sorted(by_reg.items(), key=lambda x: -len(x[1])):
            langs = Counter(s.get("lang", "?") for s in servers)
            print(f"  {reg:10s}: {len(servers):4d} servers | langs: {dict(langs)}")

        print(f"\n{'='*70}")
        print("H13: LANGUAGE DISTRIBUTION")
        print("=" * 70)
        by_lang = Counter(s.get("lang", "unknown") for s in corpus)
        for lang, count in by_lang.most_common():
            print(f"  {lang:15s}: {count:4d} ({100*count/len(corpus):.1f}%)")

        # Save lookalike results
        with open(RESULTS_DIR / "lookalikes.json", "w") as f:
            json.dump(lookalikes, f, indent=2)
