#!/usr/bin/env python3
"""
MCP-BOM Spike v2 — Full 14-hypothesis validation
Runs the extractor on the expanded corpus and adds new detectors for H5-H14.
"""

import json, os, sys, re, subprocess
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from extractor import scan_directory, compute_score, PATTERNS

OFFICIAL_DIR = "/home/ubuntu/mcp-servers-official/src"
CLONE_DIR = "/home/ubuntu/mcp-spike-repos"

# ── Full server manifest ────────────────────────────────────────────────

SERVERS = [
    # Official servers
    {"id": "mcp-filesystem", "path": f"{OFFICIAL_DIR}/filesystem", "lang": "typescript", "tier": "official-high", "desc": "Filesystem read/write/search"},
    {"id": "mcp-memory", "path": f"{OFFICIAL_DIR}/memory", "lang": "typescript", "tier": "official-high", "desc": "Knowledge graph memory"},
    {"id": "mcp-sequential-thinking", "path": f"{OFFICIAL_DIR}/sequentialthinking", "lang": "typescript", "tier": "official-high", "desc": "Sequential thinking"},
    {"id": "mcp-everything", "path": f"{OFFICIAL_DIR}/everything", "lang": "typescript", "tier": "official-high", "desc": "Test server all features"},
    {"id": "mcp-fetch", "path": f"{OFFICIAL_DIR}/fetch", "lang": "python", "tier": "official-high", "desc": "HTTP fetch"},
    {"id": "mcp-git", "path": f"{OFFICIAL_DIR}/git", "lang": "python", "tier": "official-high", "desc": "Git operations"},
    {"id": "mcp-time", "path": f"{OFFICIAL_DIR}/time", "lang": "python", "tier": "official-low", "desc": "Time queries"},
    # Previously cloned
    {"id": "mcp-shell-server", "path": f"{CLONE_DIR}/mcp-shell-server", "lang": "python", "tier": "community-low", "desc": "Shell execution"},
    {"id": "mcp-server-docker", "path": f"{CLONE_DIR}/mcp-server-docker", "lang": "python", "tier": "community-medium", "desc": "Docker management"},
    {"id": "mcp-server-mysql", "path": f"{CLONE_DIR}/mcp-server-mysql", "lang": "python", "tier": "community-medium", "desc": "MySQL database"},
    {"id": "notion-mcp-server", "path": f"{CLONE_DIR}/notion-mcp-server", "lang": "typescript", "tier": "enterprise-high", "desc": "Notion API"},
    {"id": "sentry-mcp", "path": f"{CLONE_DIR}/sentry-mcp", "lang": "typescript", "tier": "enterprise-high", "desc": "Sentry error tracking"},
    {"id": "mcp-remote", "path": f"{CLONE_DIR}/mcp-remote", "lang": "typescript", "tier": "popular-high-cve", "desc": "Remote MCP proxy (CVE)"},
    {"id": "firecrawl-mcp", "path": f"{CLONE_DIR}/firecrawl-mcp-server", "lang": "typescript", "tier": "popular-high", "desc": "Web crawling"},
    {"id": "mcp-server-kubernetes", "path": f"{CLONE_DIR}/mcp-server-kubernetes", "lang": "typescript", "tier": "popular-high", "desc": "Kubernetes management"},
    {"id": "chrome-devtools-mcp", "path": f"{CLONE_DIR}/chrome-devtools-mcp", "lang": "typescript", "tier": "popular-medium", "desc": "Chrome DevTools"},
    {"id": "python-sdk", "path": f"{CLONE_DIR}/python-sdk", "lang": "python", "tier": "official-high", "desc": "Python SDK examples"},
    # Newly cloned
    {"id": "stripe-mcp", "path": f"{CLONE_DIR}/agent-toolkit", "lang": "typescript", "tier": "enterprise-high", "desc": "Stripe payments"},
    {"id": "cloudflare-mcp", "path": f"{CLONE_DIR}/mcp-server-cloudflare", "lang": "typescript", "tier": "enterprise-high", "desc": "Cloudflare infra"},
    {"id": "supabase-mcp", "path": f"{CLONE_DIR}/supabase-mcp", "lang": "typescript", "tier": "enterprise-high", "desc": "Supabase DB/auth"},
    {"id": "linear-mcp", "path": f"{CLONE_DIR}/linear-mcp-server", "lang": "typescript", "tier": "popular-high", "desc": "Linear issues"},
    {"id": "slack-mcp-clone", "path": f"{CLONE_DIR}/slack-mcp", "lang": "typescript", "tier": "official-high", "desc": "Slack messaging"},
    {"id": "mcp-go-sdk", "path": f"{CLONE_DIR}/mcp-go", "lang": "go", "tier": "community-medium", "desc": "Go MCP SDK"},
    {"id": "mcp-playwright", "path": f"{CLONE_DIR}/mcp-playwright", "lang": "typescript", "tier": "popular-high", "desc": "Playwright browser"},
    {"id": "mongo-mcp", "path": f"{CLONE_DIR}/mongo-mcp", "lang": "typescript", "tier": "community-medium", "desc": "MongoDB server"},
    {"id": "mcp-inspector", "path": f"{CLONE_DIR}/inspector", "lang": "typescript", "tier": "official-high", "desc": "MCP Inspector (CVE)"},
    {"id": "mcp-browserbase", "path": f"{CLONE_DIR}/mcp-server-browserbase", "lang": "typescript", "tier": "popular-high", "desc": "Browserbase automation"},
    {"id": "exa-mcp", "path": f"{CLONE_DIR}/exa-mcp-server", "lang": "typescript", "tier": "popular-medium", "desc": "Exa search API"},
    {"id": "anthropic-quickstarts", "path": f"{CLONE_DIR}/anthropic-quickstarts", "lang": "python", "tier": "official-high", "desc": "Anthropic examples"},
]


def detect_extended_signals(dirpath):
    """Detect additional signals for H5-H14."""
    signals = {
        "has_approval_gate": False,       # H10
        "has_admin_db_connection": False,  # H11
        "schema_declared_tools": 0,       # H14
        "impl_detected_capabilities": 0,  # H14
        "has_interactive_prompt": False,   # H10
        "connection_string_patterns": [],  # H11
    }

    dirpath = Path(dirpath)
    for ext in ["*.py", "*.ts", "*.js", "*.go"]:
        for fpath in dirpath.rglob(ext):
            fstr = str(fpath)
            if "test" in fstr.lower() or "node_modules" in fstr or "__pycache__" in fstr:
                continue
            try:
                content = open(fpath, 'r', errors='ignore').read()
            except:
                continue

            # H10: Approval gates
            if re.search(r'\binput\s*\(', content) or re.search(r'\binquirer\b', content) or \
               re.search(r'\bconfirm\b.*\buser\b', content, re.IGNORECASE) or \
               re.search(r'\bapproval\b', content, re.IGNORECASE) or \
               re.search(r'\breadline\b', content):
                signals["has_approval_gate"] = True
            if re.search(r'\binput\s*\(', content) or re.search(r'\bprompt\s*\(', content):
                signals["has_interactive_prompt"] = True

            # H11: Admin/root DB connections
            if re.search(r'root@|user["\s]*[:=]["\s]*root|postgres://postgres|admin[:@]', content, re.IGNORECASE):
                signals["has_admin_db_connection"] = True
                signals["connection_string_patterns"].append(
                    re.findall(r'(?:root@|postgres://\w+|mysql://\w+|mongodb://\w+)[^\s"\']*', content)[:3]
                )

            # H14: Schema-declared tools (look for tools/list patterns)
            tool_list_matches = re.findall(r'(?:name|tool_name)["\s]*[:=]["\s]*["\'](\w+)', content)
            signals["schema_declared_tools"] += len(tool_list_matches)

    return signals


def get_repo_staleness(dirpath):
    """Get last commit date for staleness analysis (H9)."""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ci", "--", "."],
            capture_output=True, text=True, cwd=dirpath, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            date_str = result.stdout.strip()[:10]
            last_commit = datetime.strptime(date_str, "%Y-%m-%d")
            days_since = (datetime.now() - last_commit).days
            return {"last_commit": date_str, "days_since_update": days_since}
    except:
        pass
    return {"last_commit": "unknown", "days_since_update": -1}


def analyze_server_v2(srv):
    """Full v2 analysis of a single server."""
    path = srv["path"]
    if not os.path.exists(path):
        return None

    # Core capability scan
    raw = scan_directory(path)
    score = compute_score(raw)

    # Extended signals
    extended = detect_extended_signals(path)
    staleness = get_repo_staleness(path)

    return {
        "server_id": srv["id"],
        "lang": srv["lang"],
        "tier": srv["tier"],
        "desc": srv["desc"],
        "capability_vector": {k: bool(raw.get(k, [])) for k in PATTERNS.keys()},
        "score": score,
        "extended": extended,
        "staleness": staleness,
    }


def main():
    print("=" * 70)
    print("MCP-BOM SPIKE v2: Full 14-Hypothesis Validation")
    print("=" * 70)

    results = []
    for srv in SERVERS:
        if not os.path.exists(srv["path"]):
            continue
        print(f"  Scanning {srv['id']:30s}...", end=" ")
        analysis = analyze_server_v2(srv)
        if analysis:
            results.append(analysis)
            s = analysis["score"]
            print(f"ASS={s['attack_surface_score']:5.1f} cats={s['num_detected']} "
                  f"lang={analysis['lang']}")
        else:
            print("FAILED")

    # Save results
    output_dir = Path(__file__).parent / "results"
    output_dir.mkdir(exist_ok=True)
    with open(output_dir / "spike_v2_results.json", "w") as f:
        json.dump(results, f, indent=2)

    n = len(results)
    print(f"\n{'='*70}")
    print(f"RESULTS: {n} servers scanned")
    print(f"{'='*70}")

    # ── H1: Capability Sprawl ───────────────────────────────────────────
    cats_per_server = [r["score"]["num_detected"] for r in results]
    import numpy as np
    mean_cats = np.mean(cats_per_server)
    print(f"\nH1 (Capability Sprawl): mean categories = {mean_cats:.1f}")
    print(f"  {'SUPPORTED' if mean_cats >= 3.0 else 'NOT SUPPORTED'}: threshold was >= 3.0")

    # ── H2: Secrets Gateway ─────────────────────────────────────────────
    with_sec = [r for r in results if r["capability_vector"].get("secrets")]
    no_sec = [r for r in results if not r["capability_vector"].get("secrets")]
    if with_sec and no_sec:
        avg_sec = np.mean([r["score"]["attack_surface_score"] for r in with_sec])
        avg_nosec = np.mean([r["score"]["attack_surface_score"] for r in no_sec])
        ratio = avg_sec / avg_nosec if avg_nosec > 0 else float('inf')
        print(f"\nH2 (Secrets Gateway): with={avg_sec:.1f} without={avg_nosec:.1f} ratio={ratio:.1f}x")
        print(f"  {'SUPPORTED' if ratio >= 2.0 else 'NOT SUPPORTED'}: threshold was >= 2.0x")

    # ── H3: Language Divide ─────────────────────────────────────────────
    ts = [r for r in results if r["lang"] == "typescript"]
    py = [r for r in results if r["lang"] == "python"]
    go = [r for r in results if r["lang"] == "go"]
    if ts and py:
        ts_avg = np.mean([r["score"]["attack_surface_score"] for r in ts])
        py_avg = np.mean([r["score"]["attack_surface_score"] for r in py])
        print(f"\nH3 (Language Divide): TS={ts_avg:.1f} (n={len(ts)}) Python={py_avg:.1f} (n={len(py)})")
        if go:
            go_avg = np.mean([r["score"]["attack_surface_score"] for r in go])
            print(f"  Go={go_avg:.1f} (n={len(go)})")
        print(f"  {'SUPPORTED' if ts_avg > py_avg else 'NOT SUPPORTED'}: TS > Python")

    # ── H4: Ingress Multiplier ──────────────────────────────────────────
    with_ing = [r for r in results if r["capability_vector"].get("ingress")]
    no_ing = [r for r in results if not r["capability_vector"].get("ingress")]
    if with_ing and no_ing:
        avg_ing = np.mean([r["score"]["attack_surface_score"] for r in with_ing])
        avg_noing = np.mean([r["score"]["attack_surface_score"] for r in no_ing])
        print(f"\nH4 (Ingress Multiplier): with={avg_ing:.1f} without={avg_noing:.1f} delta={avg_ing-avg_noing:.1f}")

    # ── H5: Inverted Boundary ───────────────────────────────────────────
    both = [r for r in results if r["capability_vector"].get("ingress") and r["capability_vector"].get("delegation")]
    ing_only = [r for r in results if r["capability_vector"].get("ingress") and not r["capability_vector"].get("delegation")]
    del_only = [r for r in results if r["capability_vector"].get("delegation") and not r["capability_vector"].get("ingress")]
    print(f"\nH5 (Inverted Boundary):")
    if both: print(f"  Ingress+Delegation: avg ASS={np.mean([r['score']['attack_surface_score'] for r in both]):.1f} (n={len(both)})")
    if ing_only: print(f"  Ingress only:       avg ASS={np.mean([r['score']['attack_surface_score'] for r in ing_only]):.1f} (n={len(ing_only)})")
    if del_only: print(f"  Delegation only:    avg ASS={np.mean([r['score']['attack_surface_score'] for r in del_only]):.1f} (n={len(del_only)})")

    # ── H6: Co-Location Paradox ─────────────────────────────────────────
    sec_shell = sum(1 for r in results if r["capability_vector"].get("secrets") and r["capability_vector"].get("shell"))
    sec_total = sum(1 for r in results if r["capability_vector"].get("secrets"))
    shell_total = sum(1 for r in results if r["capability_vector"].get("shell"))
    expected = (sec_total/n) * (shell_total/n) * n if n > 0 else 0
    print(f"\nH6 (Co-Location Paradox): secrets+shell co-occur {sec_shell} times")
    print(f"  Expected by chance: {expected:.1f}")
    print(f"  {'SUPPORTED' if sec_shell > expected * 1.5 else 'INCONCLUSIVE'}: observed >> expected")

    # ── H9: Stale Server Decay ──────────────────────────────────────────
    stale = [r for r in results if r["staleness"]["days_since_update"] > 90]
    fresh = [r for r in results if 0 < r["staleness"]["days_since_update"] <= 90]
    print(f"\nH9 (Stale Server Decay):")
    if stale: print(f"  Stale (>90d): avg ASS={np.mean([r['score']['attack_surface_score'] for r in stale]):.1f} (n={len(stale)})")
    if fresh: print(f"  Fresh (<=90d): avg ASS={np.mean([r['score']['attack_surface_score'] for r in fresh]):.1f} (n={len(fresh)})")

    # ── H10: Human-in-the-Loop Illusion ─────────────────────────────────
    impersonation_servers = [r for r in results if r["capability_vector"].get("impersonation")]
    with_gate = sum(1 for r in impersonation_servers if r["extended"]["has_approval_gate"])
    print(f"\nH10 (Human-in-the-Loop Illusion):")
    print(f"  Impersonation servers: {len(impersonation_servers)}")
    print(f"  With approval gate: {with_gate}")
    print(f"  Without approval gate: {len(impersonation_servers) - with_gate}")

    # ── H11: God Mode Default ───────────────────────────────────────────
    db_servers = [r for r in results if r["capability_vector"].get("database")]
    admin_db = sum(1 for r in db_servers if r["extended"]["has_admin_db_connection"])
    print(f"\nH11 (God Mode Default):")
    print(f"  Database servers: {len(db_servers)}")
    print(f"  With admin/root connection: {admin_db}")

    # ── H13: Safe Language Fallacy ──────────────────────────────────────
    if go:
        go_avg = np.mean([r["score"]["attack_surface_score"] for r in go])
        other_avg = np.mean([r["score"]["attack_surface_score"] for r in results if r["lang"] != "go"])
        print(f"\nH13 (Safe Language Fallacy): Go={go_avg:.1f} vs Others={other_avg:.1f}")

    # ── Score Distribution ──────────────────────────────────────────────
    scores = sorted([r["score"]["attack_surface_score"] for r in results], reverse=True)
    print(f"\nOverall Score Distribution:")
    print(f"  n={n} Mean={np.mean(scores):.1f} Median={np.median(scores):.1f} Std={np.std(scores):.1f}")
    print(f"  Min={min(scores):.1f} Max={max(scores):.1f}")
    print(f"\nTop 10:")
    for r in sorted(results, key=lambda x: x["score"]["attack_surface_score"], reverse=True)[:10]:
        print(f"  {r['server_id']:30s} ASS={r['score']['attack_surface_score']:5.1f} "
              f"cats={r['score']['num_detected']} lang={r['lang']:4s} tier={r['tier']}")


if __name__ == "__main__":
    main()
