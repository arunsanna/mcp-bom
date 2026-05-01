#!/usr/bin/env python3
"""
MCP-BOM Spike Analysis
Produces visualizations and hypothesis validation from spike results.
"""

import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.style as mplstyle
mplstyle.use('seaborn-v0_8-whitegrid')
import numpy as np
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

with open(RESULTS_DIR / "spike_results.json") as f:
    results = json.load(f)

CATEGORIES = ["filesystem", "shell", "egress", "ingress", "secrets",
              "delegation", "impersonation", "data_sensitivity", "database"]

# ── Figure 1: Capability Category Prevalence ────────────────────────────

fig, ax = plt.subplots(figsize=(10, 6))
counts = {}
for cat in CATEGORIES:
    counts[cat] = sum(1 for r in results if r["capability_vector"].get(cat, False))

sorted_cats = sorted(counts.items(), key=lambda x: x[1], reverse=True)
cat_names = [c[0].replace("_", "\n") for c in sorted_cats]
cat_vals = [c[1] for c in sorted_cats]
pcts = [100 * v / len(results) for v in cat_vals]

colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(cat_names)))
bars = ax.bar(cat_names, pcts, color=colors, edgecolor='white', linewidth=0.5)

for bar, pct, cnt in zip(bars, pcts, cat_vals):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1.5,
            f'{pct:.0f}%\n({cnt}/{len(results)})',
            ha='center', va='bottom', fontsize=9, fontweight='bold')

ax.set_ylabel('Percentage of Servers (%)', fontsize=12)
ax.set_title('Capability Category Prevalence Across MCP Servers (n=16)',
             fontsize=14, fontweight='bold')
ax.set_ylim(0, 100)
ax.axhline(y=50, color='red', linestyle='--', alpha=0.3, label='50% threshold')
fig.tight_layout()
fig.savefig(FIGURES_DIR / "fig1_capability_prevalence.png", dpi=150)
print(f"Saved: fig1_capability_prevalence.png")

# ── Figure 2: Attack-Surface Score Distribution ─────────────────────────

fig, ax = plt.subplots(figsize=(12, 5))
sorted_results = sorted(results, key=lambda r: r["score"]["attack_surface_score"], reverse=True)
names = [r["server_id"].replace("mcp-", "").replace("server-", "") for r in sorted_results]
scores = [r["score"]["attack_surface_score"] for r in sorted_results]
tiers = [r.get("tier", "unknown") for r in sorted_results]

# Color by tier
tier_colors = {
    "official-high": "#2196F3",
    "official-low": "#90CAF9",
    "official-medium": "#64B5F6",
    "enterprise-high": "#FF9800",
    "popular-high": "#4CAF50",
    "popular-high-cve": "#F44336",
    "popular-medium": "#8BC34A",
    "community-low": "#9E9E9E",
    "community-medium": "#757575",
}
bar_colors = [tier_colors.get(t, "#BDBDBD") for t in tiers]

bars = ax.barh(range(len(names)), scores, color=bar_colors, edgecolor='white', linewidth=0.5)
ax.set_yticks(range(len(names)))
ax.set_yticklabels(names, fontsize=9)
ax.set_xlabel('Attack-Surface Score (0-100)', fontsize=12)
ax.set_title('MCP-BOM Attack-Surface Scores (Spike Sample, n=16)',
             fontsize=14, fontweight='bold')
ax.invert_yaxis()

# Add score labels
for i, (bar, score) in enumerate(zip(bars, scores)):
    ax.text(score + 0.5, i, f'{score:.1f}', va='center', fontsize=9)

# Legend
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='#2196F3', label='Official'),
    Patch(facecolor='#FF9800', label='Enterprise'),
    Patch(facecolor='#4CAF50', label='Popular'),
    Patch(facecolor='#F44336', label='CVE-affected'),
    Patch(facecolor='#9E9E9E', label='Community'),
]
ax.legend(handles=legend_elements, loc='lower right', fontsize=9)
ax.set_xlim(0, 70)
fig.tight_layout()
fig.savefig(FIGURES_DIR / "fig2_score_distribution.png", dpi=150)
print(f"Saved: fig2_score_distribution.png")

# ── Figure 3: Capability Heatmap ────────────────────────────────────────

fig, ax = plt.subplots(figsize=(12, 7))
matrix = []
server_names = []
for r in sorted_results:
    row = [1 if r["capability_vector"].get(cat, False) else 0 for cat in CATEGORIES]
    matrix.append(row)
    server_names.append(r["server_id"].replace("mcp-", "").replace("server-", ""))

matrix = np.array(matrix)
im = ax.imshow(matrix, cmap='RdYlGn_r', aspect='auto', interpolation='nearest')

ax.set_xticks(range(len(CATEGORIES)))
ax.set_xticklabels([c.replace("_", "\n") for c in CATEGORIES], fontsize=9, rotation=0)
ax.set_yticks(range(len(server_names)))
ax.set_yticklabels(server_names, fontsize=9)

# Add score annotations on the right
for i, r in enumerate(sorted_results):
    score = r["score"]["attack_surface_score"]
    ax.text(len(CATEGORIES) + 0.3, i, f'ASS={score:.0f}', va='center', fontsize=8,
            fontweight='bold', color='#333')

ax.set_title('Capability Detection Heatmap (sorted by ASS descending)',
             fontsize=14, fontweight='bold')
ax.set_xlim(-0.5, len(CATEGORIES) + 2)
fig.colorbar(im, ax=ax, label='Detected (1) / Not Detected (0)', shrink=0.6)
fig.tight_layout()
fig.savefig(FIGURES_DIR / "fig3_capability_heatmap.png", dpi=150)
print(f"Saved: fig3_capability_heatmap.png")

# ── Figure 4: Score Components Breakdown ────────────────────────────────

fig, ax = plt.subplots(figsize=(12, 6))
breadth = [r["score"]["breadth"] for r in sorted_results]
depth = [r["score"]["depth"] for r in sorted_results]
exposure = [r["score"]["exposure"] for r in sorted_results]

x = np.arange(len(names))
width = 0.25

bars1 = ax.bar(x - width, breadth, width, label='Breadth (w=0.20)', color='#2196F3', alpha=0.8)
bars2 = ax.bar(x, depth, width, label='Depth (w=0.45)', color='#F44336', alpha=0.8)
bars3 = ax.bar(x + width, exposure, width, label='Exposure (w=0.20)', color='#FF9800', alpha=0.8)

ax.set_xticks(x)
ax.set_xticklabels(names, fontsize=8, rotation=45, ha='right')
ax.set_ylabel('Component Score (0-100)', fontsize=11)
ax.set_title('Score Component Breakdown by Server', fontsize=14, fontweight='bold')
ax.legend(fontsize=10)
fig.tight_layout()
fig.savefig(FIGURES_DIR / "fig4_score_components.png", dpi=150)
print(f"Saved: fig4_score_components.png")

# ── Print Summary Statistics ────────────────────────────────────────────

print("\n" + "=" * 70)
print("SPIKE ANALYSIS SUMMARY")
print("=" * 70)

print(f"\nTotal servers analyzed: {len(results)}")
print(f"\nCapability prevalence (sorted):")
for cat, cnt in sorted_cats:
    print(f"  {cat:20s}: {cnt:2d}/{len(results)} ({100*cnt/len(results):5.1f}%)")

print(f"\nScore statistics:")
all_scores = [r["score"]["attack_surface_score"] for r in results]
print(f"  Mean:   {np.mean(all_scores):.1f}")
print(f"  Median: {np.median(all_scores):.1f}")
print(f"  Std:    {np.std(all_scores):.1f}")
print(f"  Min:    {min(all_scores):.1f}")
print(f"  Max:    {max(all_scores):.1f}")

print(f"\nKey finding for H1 (revised):")
print(f"  Filesystem is MORE common ({counts['filesystem']}) than Shell ({counts['shell']})")
print(f"  BUT: Secrets ({counts['secrets']}) and Egress ({counts['egress']}) are also very common")
print(f"  The real story: MCP servers are MULTI-CAPABILITY by default")
avg_cats = np.mean([r["score"]["num_detected"] for r in results])
print(f"  Average categories per server: {avg_cats:.1f} out of 9")

print(f"\nKey finding for H3 (Popularity Penalty):")
high = [r for r in results if "high" in r.get("tier", "")]
low = [r for r in results if "low" in r.get("tier", "") or "medium" in r.get("tier", "")]
if high and low:
    print(f"  High-tier avg: {np.mean([r['score']['attack_surface_score'] for r in high]):.1f}")
    print(f"  Low/Med-tier avg: {np.mean([r['score']['attack_surface_score'] for r in low]):.1f}")

print(f"\nTop 5 highest-scoring servers:")
for r in sorted_results[:5]:
    print(f"  {r['server_id']:30s} ASS={r['score']['attack_surface_score']:.1f} "
          f"cats={r['score']['num_detected']}")

print(f"\nBottom 5 lowest-scoring servers:")
for r in sorted_results[-5:]:
    print(f"  {r['server_id']:30s} ASS={r['score']['attack_surface_score']:.1f} "
          f"cats={r['score']['num_detected']}")
