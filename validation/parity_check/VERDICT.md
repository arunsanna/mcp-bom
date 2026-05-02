# Parity Check Verdict: INCONCLUSIVE

**Date:** 2026-05-02
**Comparing:** `spike/extractor.py` (reference, n=27) vs `extractor/mcp_bom/extractor.py` (port, n=298)
**Verdict:** INCONCLUSIVE — systematic under-detection with identified root causes

## TL;DR

The port extractor is **not equivalent** to the spike. Two categories (filesystem, secrets) show systematic false negatives due to architectural design choices in the port, not bugs. The port is intentionally more conservative. Whether this is acceptable depends on the construct definition (code-level risk vs tool-level capability).

## Evidence

### Anchor comparison (5 reference servers)

| Anchor | Spike categories | Port categories | Divergent |
|--------|-----------------|-----------------|-----------|
| mcp-everything | 6 | 3 | filesystem, secrets |
| mcp-fetch | 1 | 1 | — (perfect) |
| mcp-filesystem | 4 | 2 | filesystem, egress |
| mcp-shell-server | 3 | 1 | filesystem, secrets |
| notion-mcp-server | 5 | 3 | filesystem, secrets |

**Perfect matches: 1/5.** Filesystem is lost in all 4 anchors where spike detected it. Secrets lost in 3/3.

### Spot-check (4 random corpus servers + manual grep)

All 4 spot-check servers have filesystem operations visible to `grep` that the port misses. 3/4 miss secrets (env var access). This confirms the anchor finding on independent data.

### Prevalence shifts

| Category | Spike (n=27) | Port (n=298) | Delta |
|----------|-------------|-------------|-------|
| **filesystem** | 70.4% | 4.7% | **-65.7pp** |
| **secrets** | 74.1% | 6.0% | **-68.1pp** |
| ingress | 55.6% | 27.9% | -27.7pp |
| shell | 37.0% | 47.0% | +10.0pp |
| egress | 70.4% | 62.8% | -7.6pp |
| data_sensitivity | 59.3% | 51.3% | -8.0pp |

## Root causes

1. **Tool-scope gating (primary):** Port's `near_tool_reg()` restricts detection to code within/near MCP tool registrations. Module-level initialization, constructors, and helper functions are invisible. This accounts for most filesystem and secrets false negatives.

2. **Schema patterns dropped (secondary):** Spike matched JSON schema property names ("path", "command", "url"); port has zero schema patterns. Removes a detection layer that doesn't depend on code structure.

3. **Comment/string stripping (tertiary):** `strip_comments_and_strings()` blanks docstrings before matching. Minor true-positive loss.

## Construct validity question

The port's tool-scope gating is a **design choice**, not a defect. It depends on what the instrument claims to measure:

- **If ASS measures "tool-declared capabilities"** → port is more valid (no false positives from non-tool code)
- **If ASS measures "code-level attack surface"** → spike is more valid (catches all code paths)

This must be resolved before the confirmatory experiment. The score function spec (`docs/score-function.md`) should be explicit about the construct.

## Recommendations

1. **Define the construct** in `docs/score-function.md`: tool-level vs code-level
2. **Add a dual-mode flag** to the extractor: `--scope tool` (current) and `--scope code` (spike-like)
3. **Re-add schema patterns** as a separate ungated detection layer
4. **Validate tool-boundary detection** precision/recall as part of instrument validation (phase 6)
5. **Document in threats-to-validity** that tool-scope gating may undercount capabilities in servers that do setup outside tool handlers

## Artifacts

- Full diff: `validation/extractor_port_diff.txt`
- Metrics: `validation/parity_check/_metrics.json`
- Anchor outputs: `validation/parity_check/{server}.spike.json` / `{server}.port.json`
- Run metrics: `corpus/scored/_run_metrics.json`
