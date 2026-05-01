#!/usr/bin/env python3
"""
Deep analysis of spike data to discover emergent patterns for new hypotheses.
"""

import json
import numpy as np
from itertools import combinations
from collections import Counter

with open("/home/ubuntu/mcp-bom/spike/results/spike_results.json") as f:
    results = json.load(f)

CATEGORIES = ["filesystem", "shell", "egress", "ingress", "secrets",
              "delegation", "impersonation", "data_sensitivity", "database"]

print("=" * 70)
print("DEEP PATTERN ANALYSIS FOR HYPOTHESIS GENERATION")
print("=" * 70)

# ── 1. Co-occurrence Matrix ─────────────────────────────────────────────
print("\n1. CAPABILITY CO-OCCURRENCE MATRIX")
print("-" * 50)
n = len(results)
cooccur = np.zeros((len(CATEGORIES), len(CATEGORIES)))
for r in results:
    cv = r["capability_vector"]
    detected = [i for i, c in enumerate(CATEGORIES) if cv.get(c, False)]
    for i in detected:
        for j in detected:
            cooccur[i][j] += 1

print(f"{'':20s}", end="")
for c in CATEGORIES:
    print(f"{c[:6]:>7s}", end="")
print()
for i, c in enumerate(CATEGORIES):
    print(f"{c:20s}", end="")
    for j in range(len(CATEGORIES)):
        if cooccur[i][i] > 0:
            pct = 100 * cooccur[i][j] / cooccur[i][i]
            print(f"{pct:6.0f}%", end="")
        else:
            print(f"{'N/A':>7s}", end="")
    print()

# ── 2. Capability Clusters ──────────────────────────────────────────────
print("\n2. CAPABILITY CLUSTER ANALYSIS")
print("-" * 50)
# What sets of capabilities tend to appear together?
cap_sets = []
for r in results:
    cv = r["capability_vector"]
    detected = frozenset(c for c in CATEGORIES if cv.get(c, False))
    cap_sets.append((r["server_id"], detected, r["score"]["attack_surface_score"]))

# Most common pairs
pair_counts = Counter()
for _, detected, _ in cap_sets:
    for pair in combinations(detected, 2):
        pair_counts[tuple(sorted(pair))] += 1

print("Most common capability pairs:")
for pair, count in pair_counts.most_common(10):
    print(f"  {pair[0]:20s} + {pair[1]:20s} : {count}/{n} ({100*count/n:.0f}%)")

# Most common triples
triple_counts = Counter()
for _, detected, _ in cap_sets:
    for triple in combinations(detected, 3):
        triple_counts[tuple(sorted(triple))] += 1

print("\nMost common capability triples:")
for triple, count in triple_counts.most_common(5):
    print(f"  {' + '.join(triple)} : {count}/{n} ({100*count/n:.0f}%)")

# ── 3. Score Decomposition ──────────────────────────────────────────────
print("\n3. WHAT DRIVES HIGH SCORES?")
print("-" * 50)
# For each server, what's the dominant score component?
for r in sorted(results, key=lambda x: x["score"]["attack_surface_score"], reverse=True)[:8]:
    s = r["score"]
    weighted_b = 0.20 * s["breadth"]
    weighted_d = 0.45 * s["depth"]
    weighted_e = 0.20 * s["exposure"]
    weighted_p = 0.15 * s["provenance"]
    total = s["attack_surface_score"]
    dominant = max([("Breadth", weighted_b), ("Depth", weighted_d),
                    ("Exposure", weighted_e), ("Provenance", weighted_p)],
                   key=lambda x: x[1])
    print(f"  {r['server_id']:25s} ASS={total:5.1f} | "
          f"B={weighted_b:4.1f} D={weighted_d:4.1f} E={weighted_e:4.1f} P={weighted_p:4.1f} "
          f"| Dominant: {dominant[0]}")

# ── 4. Language Comparison ──────────────────────────────────────────────
print("\n4. LANGUAGE COMPARISON")
print("-" * 50)
py_servers = [r for r in results if r.get("lang") == "python"]
ts_servers = [r for r in results if r.get("lang") == "typescript"]
if py_servers and ts_servers:
    py_avg = np.mean([r["score"]["attack_surface_score"] for r in py_servers])
    ts_avg = np.mean([r["score"]["attack_surface_score"] for r in ts_servers])
    py_cats = np.mean([r["score"]["num_detected"] for r in py_servers])
    ts_cats = np.mean([r["score"]["num_detected"] for r in ts_servers])
    print(f"  Python servers (n={len(py_servers)}):     avg ASS={py_avg:.1f}, avg categories={py_cats:.1f}")
    print(f"  TypeScript servers (n={len(ts_servers)}): avg ASS={ts_avg:.1f}, avg categories={ts_cats:.1f}")

# ── 5. Secrets as Gateway ───────────────────────────────────────────────
print("\n5. SECRETS AS GATEWAY PATTERN")
print("-" * 50)
secrets_servers = [r for r in results if r["capability_vector"].get("secrets", False)]
no_secrets = [r for r in results if not r["capability_vector"].get("secrets", False)]
if secrets_servers and no_secrets:
    sec_avg = np.mean([r["score"]["attack_surface_score"] for r in secrets_servers])
    nosec_avg = np.mean([r["score"]["attack_surface_score"] for r in no_secrets])
    sec_cats = np.mean([r["score"]["num_detected"] for r in secrets_servers])
    nosec_cats = np.mean([r["score"]["num_detected"] for r in no_secrets])
    print(f"  With secrets (n={len(secrets_servers)}):    avg ASS={sec_avg:.1f}, avg categories={sec_cats:.1f}")
    print(f"  Without secrets (n={len(no_secrets)}): avg ASS={nosec_avg:.1f}, avg categories={nosec_cats:.1f}")
    print(f"  Secrets access correlates with {sec_cats/nosec_cats:.1f}x more capability categories")

# ── 6. The "Kitchen Sink" Pattern ───────────────────────────────────────
print("\n6. THE KITCHEN SINK PATTERN")
print("-" * 50)
for r in sorted(results, key=lambda x: x["score"]["num_detected"], reverse=True):
    cats = r["score"]["num_detected"]
    score = r["score"]["attack_surface_score"]
    tier = r.get("tier", "?")
    print(f"  {r['server_id']:25s} categories={cats}/9  ASS={score:5.1f}  tier={tier}")

# ── 7. Ingress as Risk Multiplier ───────────────────────────────────────
print("\n7. INGRESS AS RISK MULTIPLIER")
print("-" * 50)
ingress_servers = [r for r in results if r["capability_vector"].get("ingress", False)]
no_ingress = [r for r in results if not r["capability_vector"].get("ingress", False)]
if ingress_servers and no_ingress:
    ing_avg = np.mean([r["score"]["attack_surface_score"] for r in ingress_servers])
    noing_avg = np.mean([r["score"]["attack_surface_score"] for r in no_ingress])
    print(f"  With ingress (n={len(ingress_servers)}):    avg ASS={ing_avg:.1f}")
    print(f"  Without ingress (n={len(no_ingress)}): avg ASS={noing_avg:.1f}")
    print(f"  Ingress adds {ing_avg - noing_avg:.1f} points to average score")

# ── 8. Category Count vs Score Correlation ──────────────────────────────
print("\n8. CATEGORY COUNT vs SCORE CORRELATION")
print("-" * 50)
cat_counts = [r["score"]["num_detected"] for r in results]
scores = [r["score"]["attack_surface_score"] for r in results]
correlation = np.corrcoef(cat_counts, scores)[0, 1]
print(f"  Pearson r = {correlation:.3f}")
print(f"  This means: {'Strong' if abs(correlation) > 0.7 else 'Moderate' if abs(correlation) > 0.4 else 'Weak'} "
      f"{'positive' if correlation > 0 else 'negative'} correlation")
