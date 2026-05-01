#!/usr/bin/env python3
"""
MCP-BOM Spike Extractor
Lightweight capability detector for the 9-category taxonomy.
Scans source files for API patterns indicating each capability category.
"""

import os
import re
import json
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Pattern Definitions (per category) ──────────────────────────────────

PATTERNS = {
    "filesystem": {
        "python": [
            r'\bopen\s*\(', r'\bpathlib\.Path\b', r'\bos\.path\b', r'\bshutil\b',
            r'\bos\.remove\b', r'\bos\.unlink\b', r'\baiofiles\b', r'\bos\.listdir\b',
            r'\bos\.walk\b', r'\bglob\.glob\b', r'\bos\.makedirs\b',
            r'\bos\.rename\b', r'\bos\.stat\b',
        ],
        "typescript": [
            r'\bfs\b', r'\bfs/promises\b', r'\bfs\.read', r'\bfs\.write',
            r'\bfs\.unlink\b', r'\bfs\.mkdir\b', r'\bfs\.readdir\b',
            r'\breadFile\b', r'\bwriteFile\b', r'\bnode:fs\b',
            r'\bcreateReadStream\b', r'\bcreateWriteStream\b',
        ],
        "schema": [
            r'"path"', r'"filename"', r'"directory"', r'"file_url"',
            r'"file_path"', r'"filepath"',
        ],
    },
    "shell": {
        "python": [
            r'\bsubprocess\.run\b', r'\bsubprocess\.Popen\b', r'\bsubprocess\.call\b',
            r'\bos\.system\b', r'\bos\.exec', r'\bos\.popen\b',
            r'\bpty\.spawn\b', r'\beval\s*\(', r'\bexec\s*\(',
            r'\bpickle\.load', r'\byaml\.unsafe_load\b', r'\byaml\.full_load\b',
        ],
        "typescript": [
            r'\bchild_process\b', r'\bexecSync\b', r'\bspawnSync\b',
            r'\bexec\s*\(', r'\bspawn\s*\(', r'\bshelljs\b',
            r'\bexecFile\b',
        ],
        "schema": [
            r'"command"', r'"shell"', r'"script"', r'"execute"',
            r'"run_command"', r'"exec"',
        ],
    },
    "egress": {
        "python": [
            r'\brequests\b', r'\bhttpx\b', r'\burllib\b', r'\baiohttp\b',
            r'\bsocket\.connect\b', r'\bhttp\.client\b',
        ],
        "typescript": [
            r'\bfetch\s*\(', r'\baxios\b', r'\bnode-fetch\b',
            r'\bhttp\.request\b', r'\bhttps\.request\b', r'\bgot\b',
        ],
        "schema": [
            r'"url"', r'"endpoint"', r'"api_url"', r'"webhook"',
        ],
    },
    "ingress": {
        "python": [
            r'\bFlask\b', r'\bFastAPI\b', r'\buvicorn\b',
            r'\.listen\s*\(', r'0\.0\.0\.0',
        ],
        "typescript": [
            r'\bexpress\b', r'\bfastify\b', r'\bhono\b',
            r'\.listen\s*\(', r'0\.0\.0\.0',
        ],
        "schema": [],
    },
    "secrets": {
        "python": [
            r'\bos\.environ\b', r'\bos\.getenv\b', r'\bdotenv\b',
            r'\bkeyring\b', r'\bboto3\b.*secret', r'\bazure.*keyvault\b',
        ],
        "typescript": [
            r'\bprocess\.env\b', r'\bdotenv\b',
            r'\bAWS\.SecretsManager\b',
        ],
        "schema": [
            r'"api_key"', r'"token"', r'"secret"', r'"password"',
            r'"credential"',
        ],
    },
    "delegation": {
        "python": [
            r'\bmcp\.ClientSession\b', r'\bClientSession\b',
            r'\bStdioServerParameters\b',
        ],
        "typescript": [
            r'@modelcontextprotocol/sdk.*[Cc]lient', r'\bClient\b.*mcp',
            r'\bStdioClientTransport\b', r'\bSSEClientTransport\b',
        ],
        "schema": [
            r'"mcp_server"', r'"server_url"',
        ],
    },
    "impersonation": {
        "python": [
            r'\bsmtplib\b', r'\bimaplib\b', r'\bgoogleapiclient\b',
            r'\bslack_sdk\b', r'\btweepy\b', r'\bdiscord\b',
        ],
        "typescript": [
            r'\bnodemailer\b', r'\b@slack/web-api\b', r'\bdiscord\.js\b',
            r'\btwit\b', r'\btwitter-api\b',
        ],
        "schema": [
            r'"send_email"', r'"send_message"', r'"post"', r'"publish"',
            r'"tweet"', r'"send_slack"',
        ],
    },
    "data_sensitivity": {
        "python": [
            r'\bcryptography\b', r'\bhashlib\b', r'\bfernet\b',
        ],
        "typescript": [
            r'\bcrypto\b', r'\bbcrypt\b',
        ],
        "schema": [
            r'"email"', r'"phone"', r'"address"', r'"ssn"',
            r'"credit_card"', r'"patient"',
        ],
    },
    "database": {
        "python": [
            r'\bsqlite3\b', r'\bpsycopg\b', r'\bSQLAlchemy\b', r'\bsqlalchemy\b',
            r'\bpymongo\b', r'\bredis\b', r'\bmotor\b', r'\bmysql\b',
            r'\baiosqlite\b',
        ],
        "typescript": [
            r'\bpg\b', r'\bmysql2\b', r'\bmongoose\b', r'\bprisma\b',
            r'\btypeorm\b', r'\bdrizzle\b', r'\bbetter-sqlite3\b',
            r'\bknex\b',
        ],
        "schema": [
            r'"query"', r'"sql"', r'"database"', r'"table"',
            r'"collection"',
        ],
    },
}

# ── Depth Scoring (from score-function.md) ──────────────────────────────

def compute_depth(category: str, detected_patterns: list) -> float:
    """Simplified depth scoring based on detected patterns."""
    pat_str = " ".join(detected_patterns).lower()

    if category == "filesystem":
        score = 2  # read baseline
        if any(w in pat_str for w in ["write", "writefile", "createwritestream", "makedirs", "rename"]):
            score = 5
        if any(w in pat_str for w in ["remove", "unlink", "delete", "rmdir"]):
            score = 8
        return score

    elif category == "shell":
        score = 4  # sandboxed baseline
        if any(w in pat_str for w in ["subprocess", "child_process", "exec", "spawn", "os.system", "popen"]):
            score = 8
        if any(w in pat_str for w in ["shell=true", "shell_interpreted", "eval", "pickle", "unsafe_load"]):
            score += 2
        return min(score, 10)

    elif category == "egress":
        score = 2  # allowlisted baseline
        if any(w in pat_str for w in ["url", "endpoint", "arbitrary", "fetch", "requests", "httpx", "axios"]):
            score = 8
        return score

    elif category == "ingress":
        score = 1
        if "0.0.0.0" in pat_str:
            score = 10
        elif "listen" in pat_str:
            score = 4
        return score

    elif category == "secrets":
        score = 3  # process env read
        if any(w in pat_str for w in ["keyvault", "secretsmanager", "keyring"]):
            score = 8
        return score

    elif category == "delegation":
        score = 3  # static
        if any(w in pat_str for w in ["dynamic", "runtime"]):
            score = 7
        return score

    elif category == "impersonation":
        score = 3  # per channel
        channels = sum(1 for w in ["smtp", "slack", "discord", "tweet", "email", "nodemailer"]
                       if w in pat_str)
        score = min(3 * max(channels, 1), 9)
        return score

    elif category == "data_sensitivity":
        score = 0
        if any(w in pat_str for w in ["ssn", "credit_card", "patient"]):
            score = 9
        elif any(w in pat_str for w in ["email", "phone", "address"]):
            score = 7
        elif any(w in pat_str for w in ["crypto", "hash", "fernet"]):
            score = 4
        return score

    elif category == "database":
        score = 2  # read baseline
        if any(w in pat_str for w in ["write", "insert", "update", "delete", "drop"]):
            score = 6
        if any(w in pat_str for w in ["sql", "query", "execute"]):
            score = max(score, 5)
        return score

    return 0


def scan_file(filepath: str, lang: str) -> dict:
    """Scan a single file for capability patterns."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except Exception:
        return {}

    results = {}
    for category, lang_patterns in PATTERNS.items():
        # Combine language-specific + schema patterns
        patterns_to_check = lang_patterns.get(lang, []) + lang_patterns.get("schema", [])
        matches = []
        for pat in patterns_to_check:
            found = re.findall(pat, content, re.IGNORECASE)
            if found:
                matches.extend(found)
        if matches:
            results[category] = matches

    return results


def scan_directory(dirpath: str) -> dict:
    """Scan all source files in a directory."""
    all_results = {}
    dirpath = Path(dirpath)

    for ext, lang in [(".py", "python"), (".ts", "typescript"), (".js", "typescript")]:
        for fpath in dirpath.rglob(f"*{ext}"):
            # Skip test files and node_modules
            fstr = str(fpath)
            if "test" in fstr.lower() or "node_modules" in fstr or "__pycache__" in fstr:
                continue
            file_results = scan_file(str(fpath), lang)
            for cat, matches in file_results.items():
                if cat not in all_results:
                    all_results[cat] = []
                all_results[cat].extend(matches)

    return all_results


def compute_score(capability_vector: dict) -> dict:
    """Compute the 0-100 attack-surface score."""
    detected_categories = [c for c, m in capability_vector.items() if m]
    num_categories = 9

    # Component 1: Breadth
    B = (len(detected_categories) / num_categories) * 100

    # Component 2: Depth
    total_depth = 0
    max_possible_depth = num_categories * 10  # 90
    for cat in detected_categories:
        depth = compute_depth(cat, capability_vector.get(cat, []))
        total_depth += depth
    D = (total_depth / max_possible_depth) * 100

    # Component 3: Exposure (simplified - check for ingress patterns)
    E = 0
    if "ingress" in detected_categories:
        ingress_pats = " ".join(capability_vector.get("ingress", [])).lower()
        if "0.0.0.0" in ingress_pats:
            E = 100
        else:
            E = 40

    # Component 4: Provenance (placeholder - would need install count data)
    P = 35  # default: unsigned + active maintenance

    # Weighted sum
    w_b, w_d, w_e, w_p = 0.20, 0.45, 0.20, 0.15
    ASS = w_b * B + w_d * D + w_e * E + w_p * P

    return {
        "breadth": round(B, 1),
        "depth": round(D, 1),
        "exposure": round(E, 1),
        "provenance": round(P, 1),
        "attack_surface_score": round(ASS, 1),
        "detected_categories": detected_categories,
        "num_detected": len(detected_categories),
    }


def analyze_server(server_path: str, server_id: str) -> dict:
    """Full analysis of a single server."""
    raw = scan_directory(server_path)

    # Build capability vector (category -> detected True/False + pattern list)
    capability_vector = {}
    for cat in PATTERNS.keys():
        matches = raw.get(cat, [])
        capability_vector[cat] = [str(m)[:60] for m in matches[:10]]  # truncate

    score = compute_score(raw)

    return {
        "server_id": server_id,
        "path": server_path,
        "capability_vector": {k: bool(v) for k, v in raw.items()},
        "pattern_details": capability_vector,
        "score": score,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extractor.py <server_path> <server_id>")
        sys.exit(1)

    result = analyze_server(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=2))
