#!/usr/bin/env python3
"""
MCP-BOM Spike v3 — Resolve all 7 remaining hypotheses
Clones a strategic subset from the scraped corpus and runs full analysis.
"""

import json, os, sys, subprocess, re
from pathlib import Path
from collections import Counter
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from extractor import scan_directory, compute_score, PATTERNS
from hypothesis_tooling import (
    detect_lookalikes, detect_schema_drift,
    detect_approval_patterns, run_semgrep_on_dir
)

RESULTS_DIR = Path(__file__).parent / "results"
CLONE_DIR = "/home/ubuntu/mcp-spike-repos"

# Load the v2 results as our base
with open(RESULTS_DIR / "spike_v2_results.json") as f:
    base_results = json.load(f)

# Additional servers to clone for specific hypotheses
ADDITIONAL_CLONES = [
    # More impersonation servers (H10)
    {"id": "resend-mcp", "repo": "https://github.com/resend/mcp-send-email", "lang": "typescript", "tier": "enterprise-high", "desc": "Resend email sending"},
    {"id": "twilio-mcp", "repo": "https://github.com/twilio-labs/mcp-server-twilio", "lang": "typescript", "tier": "enterprise-high", "desc": "Twilio SMS/voice"},
    # More database servers (H6, H11)
    {"id": "neon-mcp", "repo": "https://github.com/neondatabase/mcp-server-neon", "lang": "typescript", "tier": "enterprise-high", "desc": "Neon Postgres"},
    {"id": "turso-mcp", "repo": "https://github.com/tursodatabase/turso-mcp", "lang": "typescript", "tier": "enterprise-high", "desc": "Turso SQLite edge"},
    # More Go servers (H13)
    {"id": "go-mcp-filesystem", "repo": "https://github.com/mark3labs/mcp-filesystem-server", "lang": "go", "tier": "community-medium", "desc": "Go filesystem server"},
    # More shell/exec servers (H6)
    {"id": "mcp-nixos", "repo": "https://github.com/utensils/mcp-nixos", "lang": "python", "tier": "community-medium", "desc": "NixOS system management"},
]


def clone_additional():
    """Clone additional servers needed for hypothesis testing."""
    os.makedirs(CLONE_DIR, exist_ok=True)
    cloned = []
    for srv in ADDITIONAL_CLONES:
        dest = os.path.join(CLONE_DIR, srv["id"])
        if not os.path.exists(dest):
            print(f"  Cloning {srv['id']}...")
            try:
                subprocess.run(["git", "clone", "--depth", "1", srv["repo"], dest],
                               capture_output=True, timeout=60)
            except:
                pass
        if os.path.exists(dest):
            srv["path"] = dest
            cloned.append(srv)
    return cloned


def scan_server_full(srv):
    """Full scan with all detectors."""
    path = srv["path"]
    if not os.path.exists(path):
        return None

    raw = scan_directory(path)
    score = compute_score(raw)
    drift = detect_schema_drift(path)
    approval = detect_approval_patterns(path)

    return {
        "server_id": srv["id"],
        "lang": srv.get("lang", "unknown"),
        "tier": srv.get("tier", "unknown"),
        "desc": srv.get("desc", ""),
        "capability_vector": {k: bool(raw.get(k, [])) for k in PATTERNS.keys()},
        "score": score,
        "schema_drift": drift,
        "approval_gates": approval,
    }


def main():
    print("=" * 70)
    print("MCP-BOM SPIKE v3: Resolving 7 Remaining Hypotheses")
    print("=" * 70)

    # Clone additional servers
    print("\n[1/4] Cloning additional servers...")
    new_servers = clone_additional()
    print(f"  Cloned {len(new_servers)} additional servers")

    # Scan new servers
    print("\n[2/4] Scanning new servers...")
    new_results = []
    for srv in new_servers:
        print(f"  Scanning {srv['id']:30s}...", end=" ")
        analysis = scan_server_full(srv)
        if analysis:
            new_results.append(analysis)
            print(f"ASS={analysis['score']['attack_surface_score']:5.1f}")
        else:
            print("FAILED")

    # Also run schema drift and approval detection on existing servers
    print("\n[3/4] Running extended analysis on existing servers...")
    existing_paths = {
        "mcp-filesystem": f"/home/ubuntu/mcp-servers-official/src/filesystem",
        "mcp-fetch": f"/home/ubuntu/mcp-servers-official/src/fetch",
        "mcp-git": f"/home/ubuntu/mcp-servers-official/src/git",
        "mcp-everything": f"/home/ubuntu/mcp-servers-official/src/everything",
        "mcp-time": f"/home/ubuntu/mcp-servers-official/src/time",
        "mcp-memory": f"/home/ubuntu/mcp-servers-official/src/memory",
        "mcp-shell-server": f"{CLONE_DIR}/mcp-shell-server",
        "notion-mcp-server": f"{CLONE_DIR}/notion-mcp-server",
        "sentry-mcp": f"{CLONE_DIR}/sentry-mcp",
        "mcp-remote": f"{CLONE_DIR}/mcp-remote",
        "firecrawl-mcp": f"{CLONE_DIR}/firecrawl-mcp-server",
        "mcp-server-kubernetes": f"{CLONE_DIR}/mcp-server-kubernetes",
        "supabase-mcp": f"{CLONE_DIR}/supabase-mcp",
        "slack-mcp-clone": f"{CLONE_DIR}/slack-mcp",
        "mcp-inspector": f"{CLONE_DIR}/inspector",
        "mcp-browserbase": f"{CLONE_DIR}/mcp-server-browserbase",
        "stripe-mcp": f"{CLONE_DIR}/agent-toolkit",
        "cloudflare-mcp": f"{CLONE_DIR}/mcp-server-cloudflare",
        "mcp-playwright": f"{CLONE_DIR}/mcp-playwright",
        "mcp-go-sdk": f"{CLONE_DIR}/mcp-go",
        "mongo-mcp": f"{CLONE_DIR}/mongo-mcp",
        "exa-mcp": f"{CLONE_DIR}/exa-mcp-server",
    }

    drift_results = {}
    approval_results = {}
    semgrep_results = {}

    for sid, path in existing_paths.items():
        if os.path.exists(path):
            drift_results[sid] = detect_schema_drift(path)
            approval_results[sid] = detect_approval_patterns(path)

    # Add new server results
    for r in new_results:
        drift_results[r["server_id"]] = r["schema_drift"]
        approval_results[r["server_id"]] = r["approval_gates"]

    # Run Semgrep on a subset (H12)
    print("\n  Running Semgrep on 10-server subset for H12...")
    semgrep_subset = list(existing_paths.items())[:10]
    for sid, path in semgrep_subset:
        if os.path.exists(path):
            print(f"    Semgrep: {sid}...", end=" ")
            result = run_semgrep_on_dir(path)
            semgrep_results[sid] = result
            total = result.get("total_findings", 0)
            print(f"{total} findings")

    # ── ANALYSIS ────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("HYPOTHESIS VALIDATION — REMAINING 7")
    print(f"{'='*70}")

    # Combine all results for statistical tests
    all_results = base_results + new_results
    n = len(all_results)

    # ── H6: Co-Location Paradox (larger sample) ────────────────────────
    print(f"\nH6 (Co-Location Paradox) [n={n}]:")
    sec_count = sum(1 for r in all_results if r["capability_vector"].get("secrets"))
    shell_count = sum(1 for r in all_results if r["capability_vector"].get("shell"))
    both_count = sum(1 for r in all_results if r["capability_vector"].get("secrets") and r["capability_vector"].get("shell"))
    expected = (sec_count/n) * (shell_count/n) * n if n > 0 else 0
    pmi = np.log2((both_count/n) / ((sec_count/n) * (shell_count/n))) if both_count > 0 and sec_count > 0 and shell_count > 0 else 0
    print(f"  Secrets: {sec_count}/{n} ({100*sec_count/n:.0f}%)")
    print(f"  Shell: {shell_count}/{n} ({100*shell_count/n:.0f}%)")
    print(f"  Both: {both_count}/{n} ({100*both_count/n:.0f}%)")
    print(f"  Expected by chance: {expected:.1f}")
    print(f"  PMI: {pmi:.2f}")
    print(f"  {'SUPPORTED' if both_count > expected * 1.3 and pmi > 0 else 'NOT SUPPORTED'}")

    # Also check database+shell co-location
    db_count = sum(1 for r in all_results if r["capability_vector"].get("database"))
    db_shell = sum(1 for r in all_results if r["capability_vector"].get("database") and r["capability_vector"].get("shell"))
    db_expected = (db_count/n) * (shell_count/n) * n if n > 0 else 0
    print(f"  Database+Shell: {db_shell}/{n} (expected: {db_expected:.1f})")

    # ── H7: Lookalike Risk Premium ──────────────────────────────────────
    print(f"\nH7 (Lookalike Risk Premium):")
    with open(RESULTS_DIR / "scraped_corpus.json") as f:
        corpus = json.load(f)
    lookalikes = detect_lookalikes(corpus)
    print(f"  Total lookalikes detected in corpus: {len(lookalikes)}")
    high_sim = [la for la in lookalikes if la["similarity"] >= 0.85]
    print(f"  High similarity (>=0.85): {len(high_sim)}")
    by_registry = Counter(la["registry"] for la in lookalikes)
    print(f"  By registry: {dict(by_registry)}")
    print(f"  FINDING: {len(lookalikes)} potential lookalikes across 245 servers = {100*len(lookalikes)/245:.0f}% lookalike rate")
    print(f"  Cannot compare ASS without scanning lookalikes — noted for full corpus")

    # ── H8: Registry Governance Gap ─────────────────────────────────────
    print(f"\nH8 (Registry Governance Gap):")
    npm_results = [r for r in all_results if r.get("tier", "").startswith("official") or r.get("tier", "").startswith("enterprise")]
    community_results = [r for r in all_results if r.get("tier", "").startswith("community")]
    if npm_results and community_results:
        official_scores = [r["score"]["attack_surface_score"] for r in npm_results]
        community_scores = [r["score"]["attack_surface_score"] for r in community_results]
        print(f"  Official/Enterprise (n={len(npm_results)}): mean={np.mean(official_scores):.1f} std={np.std(official_scores):.1f}")
        print(f"  Community (n={len(community_results)}): mean={np.mean(community_scores):.1f} std={np.std(community_scores):.1f}")
        print(f"  Variance ratio: {np.var(community_scores)/np.var(official_scores):.2f}x" if np.var(official_scores) > 0 else "  N/A")

    # ── H10: Human-in-the-Loop Illusion (expanded) ──────────────────────
    print(f"\nH10 (Human-in-the-Loop Illusion):")
    impersonation_servers = [r for r in all_results if r["capability_vector"].get("impersonation")]
    total_imp = len(impersonation_servers)
    with_gate = 0
    without_gate = 0
    for r in all_results:
        sid = r["server_id"]
        if r["capability_vector"].get("impersonation"):
            gate = approval_results.get(sid, {})
            if gate.get("has_any_gate", False):
                with_gate += 1
            else:
                without_gate += 1
    print(f"  Impersonation servers: {total_imp}")
    print(f"  With approval gate: {with_gate}")
    print(f"  Without approval gate: {without_gate}")
    if total_imp > 0:
        pct_no_gate = 100 * without_gate / total_imp
        print(f"  {pct_no_gate:.0f}% lack approval gates")
        print(f"  {'SUPPORTED' if pct_no_gate > 60 else 'INCONCLUSIVE'}")

    # ── H12: CWE-Capability Orthogonality ───────────────────────────────
    print(f"\nH12 (CWE-Capability Orthogonality):")
    paired_data = []
    for sid, sem in semgrep_results.items():
        if "error" in sem:
            continue
        # Find matching server in results
        matching = [r for r in all_results if r["server_id"] == sid]
        if matching:
            ass = matching[0]["score"]["attack_surface_score"]
            cwe_count = sem.get("total_findings", 0)
            paired_data.append((ass, cwe_count))
            print(f"  {sid:30s}: ASS={ass:5.1f} CWE_findings={cwe_count}")

    if len(paired_data) >= 5:
        ass_vals = [p[0] for p in paired_data]
        cwe_vals = [p[1] for p in paired_data]
        corr = np.corrcoef(ass_vals, cwe_vals)[0, 1] if np.std(cwe_vals) > 0 else 0
        print(f"  Pearson r(ASS, CWE_count) = {corr:.3f}")
        print(f"  {'SUPPORTED (orthogonal)' if abs(corr) < 0.3 else 'NOT SUPPORTED'}")
    else:
        print(f"  Only {len(paired_data)} paired samples — need more data")

    # ── H13: Safe Language Fallacy ──────────────────────────────────────
    print(f"\nH13 (Safe Language Fallacy):")
    go_results = [r for r in all_results if r.get("lang") == "go"]
    non_go = [r for r in all_results if r.get("lang") in ["python", "typescript"]]
    if go_results:
        go_avg = np.mean([r["score"]["attack_surface_score"] for r in go_results])
        non_go_avg = np.mean([r["score"]["attack_surface_score"] for r in non_go])
        print(f"  Go (n={len(go_results)}): avg ASS={go_avg:.1f}")
        print(f"  Python+TS (n={len(non_go)}): avg ASS={non_go_avg:.1f}")
        print(f"  {'SUPPORTED' if go_avg >= non_go_avg * 0.7 else 'NOT SUPPORTED'}: Go not significantly lower")
    else:
        print(f"  No Go servers in scanned set")

    # ── H14: Schema-Implementation Drift ────────────────────────────────
    print(f"\nH14 (Schema-Implementation Drift):")
    servers_with_drift = 0
    total_checked = 0
    drift_details = []
    for sid, drift in drift_results.items():
        if drift["impl_detected"]:  # Only count servers where we detected something
            total_checked += 1
            if drift["has_drift"]:
                servers_with_drift += 1
                drift_details.append((sid, drift["hidden_capabilities"]))

    if total_checked > 0:
        pct_drift = 100 * servers_with_drift / total_checked
        print(f"  Servers checked: {total_checked}")
        print(f"  Servers with hidden capabilities: {servers_with_drift} ({pct_drift:.0f}%)")
        print(f"  {'SUPPORTED' if pct_drift >= 20 else 'NOT SUPPORTED'}: threshold was >= 20%")
        for sid, hidden in drift_details[:10]:
            print(f"    {sid:30s}: hidden={hidden}")

    # Save all results
    all_output = {
        "base_results": base_results,
        "new_results": new_results,
        "drift_results": {k: v for k, v in drift_results.items()},
        "approval_results": {k: v for k, v in approval_results.items()},
        "semgrep_results": semgrep_results,
        "lookalikes_count": len(lookalikes),
        "corpus_size": len(corpus),
    }
    with open(RESULTS_DIR / "spike_v3_results.json", "w") as f:
        json.dump(all_output, f, indent=2, default=str)
    print(f"\nResults saved to spike_v3_results.json")


if __name__ == "__main__":
    main()
