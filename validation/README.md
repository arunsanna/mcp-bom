# MCP-BOM Validation Suite

Build target: Day 4 (May 4, 2026).

## Goals

- Quantify extractor reliability (inter-rater).
- Quantify score function discriminative power (MCPLIB replay).
- Spot-check score function alignment with known severe outcomes (CVE correlation).
- Quantify cross-source consistency (same server, different registry).

## Components

### Inter-Rater Reliability

- Sample: 50 servers held out from the 500-server corpus.
- Two reviewers independently label each server's capability scope vector.
- Output: Cohen's κ per category and overall.
- Target: κ ≥ 0.70 (substantial agreement).

### MCPLIB Attack Replay

- Source: arXiv:2508.12538 — 31 MCP attack types in four categories.
- Method: simulate each attack type against representative servers from each score quintile.
- Expected: high-score servers (ASS ≥ 70) succumb at higher rates than low-score servers (ASS ≤ 30).
- Output: attack success rate vs score quintile.

### CVE Correlation

- Targets: CVE-2025-6514 (`mcp-remote` RCE, CVSS 9.6), CVE-2025-49596 (MCP Inspector CSRF→RCE, CVSS 9.4).
- Method: scan the affected versions; confirm ASS ≥ 80.
- If miss: investigate which capability category was under-detected; document in limitations.

### Cross-Source Consistency

- Identify packages published in multiple registries (npm + PyPI, etc.).
- Score each variant; report score variance.
- Target: max(ASS) − min(ASS) ≤ 5 across variants of the same source.

## Layout

```
validation/
├── README.md
├── inter_rater/
│   ├── reviewer_1.json
│   ├── reviewer_2.json
│   └── kappa.py
├── mcplib_replay/
│   ├── attacks.json            from arXiv:2508.12538
│   └── results.json
├── cve_correlation/
│   └── cve_check.py
└── cross_source/
    └── variance.py
```

## Reporting

Final validation table goes into the paper Section 5 (Results) and includes:

- κ per category and overall
- Attack success rate per score quintile (table)
- CVE spot-check (pass/fail with score)
- Cross-source variance (range)

## Status

Empty pending Day 4 implementation.
