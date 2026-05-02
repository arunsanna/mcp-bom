# MCP-BOM Session Handoff

> Single source of truth for picking up work between sessions. Updated 2026-05-02 after extractor port parity restoration. This file lives in the repo intentionally — committed, versioned, and easy to find.

## Project context

- **Building**: MCP-BOM, a reproducible attack-surface benchmark for MCP servers, targeting NeurIPS 2026 Evaluations & Datasets Track.
- **Hard freeze**: May 6, 2026 AoE (4 days from now).
- **Workflow**: see repo `CLAUDE.md` — code-scope construct + pre-registration + instrument validation are mandatory gates.
- **External storage**: `/Volumes/A1` (1TB HFS+, 791GB free). Verified writable from iTerm in a fresh session.

## Where we are now

| Phase                 | State                                      | Evidence                                                                      |
| --------------------- | ------------------------------------------ | ----------------------------------------------------------------------------- |
| Pre-registration      | locked                                     | `docs/preregistration.md` — 6 confirmatory + 8 exploratory; α=0.00833         |
| Corpus manifest       | done (500 servers)                         | `corpus/manifest.json`                                                        |
| First corpus scan     | done — but **tool-scope cohort**           | `corpus/scored/*.json` (298 servers), kept as H14 baseline                    |
| Extractor parity      | **restored 2026-05-02**                    | commits `485980c`, `40978ea`, `e7e5531` — 5/5 anchors match spike             |
| External storage      | verified accessible, **not yet symlinked** | `/Volumes/A1` writable; `corpus/raw` and `corpus/cached` still on laptop disk |
| Code-scope re-scan    | not started                                | needs symlinks done first, then re-run with `--scope code`                    |
| H14 drift computation | not started                                | once both scopes are scored, drift is a set-difference per server             |
| Instrument validation | not started                                | per pre-reg §4 — 50-server hand-label, Cohen's κ ≥ 0.6                        |

## Key decisions locked

1. **ASS construct = code-level attack surface** (memory `project_construct_decision.md`). Tool-scope is opt-in, used only for H14 drift computation.
2. **Agents push to `main` directly** (memory `feedback_agent_push_policy.md`). No feature branches.
3. **External storage layout** (memory `project_storage_plan.md`):
   ```
   /Volumes/A1/mcp-bom-storage/
     scan-temp/        ← /tmp/mcp-bom-scan symlinks here
     raw-archives/     ← corpus/raw symlinks here
     cached/           ← corpus/cached symlinks here
   ```

---

## Next actions (in order)

### Step 1 — Storage setup (mechanical, ~2 min)

Run from repo root:

```bash
mkdir -p /Volumes/A1/mcp-bom-storage/{scan-temp,raw-archives,cached}

# Move existing on-disk archives to A1
[ -d corpus/raw ] && [ ! -L corpus/raw ] && mv corpus/raw/* /Volumes/A1/mcp-bom-storage/raw-archives/ 2>/dev/null && rmdir corpus/raw
[ -d corpus/cached ] && [ ! -L corpus/cached ] && mv corpus/cached/* /Volumes/A1/mcp-bom-storage/cached/ 2>/dev/null && rmdir corpus/cached

# Replace with symlinks
ln -s /Volumes/A1/mcp-bom-storage/raw-archives corpus/raw
ln -s /Volumes/A1/mcp-bom-storage/cached corpus/cached

# Verify
ls -la corpus/raw corpus/cached && df -h /Volumes/A1
```

No commit needed — `corpus/raw` and `corpus/cached` are already in `.gitignore`. Symlinks are local-only.

### Step 2 — Dispatch corpus re-scan with `--scope code`

The streaming scan driver `extractor/run_corpus_scan.py` already has the `--scope code` flag (added by commit `485980c`). Re-run on the same 316-server scannable set, but write outputs to a **new directory** so the existing 298 tool-scope results are preserved as the H14 baseline.

**Task spec to dispatch (copy-paste to delegated agent):**

```
GOAL
Re-run the corpus scan with --scope code on the 316 scannable servers
(filtered set already in validation/scannable_set.json). Write outputs
to corpus/scored_code/ — DO NOT overwrite corpus/scored/ which holds
the tool-scope baseline cohort for H14.

IMPLEMENTATION
1. Verify the symlinks from Step 1 are in place:
   readlink corpus/raw && readlink corpus/cached
   (should both point under /Volumes/A1/mcp-bom-storage/)

2. Run:
   python3 extractor/run_corpus_scan.py \
     --manifest corpus/manifest.json \
     --score-function score_function.toml \
     --scope code \
     --output-dir corpus/scored_code \
     --cache-dir corpus/cached \
     --temp-dir /Volumes/A1/mcp-bom-storage/scan-temp \
     --workers 4

3. Same retention rules as prior run (labeled 50-server subset, top-20
   outliers, errored). Reuse cached archives where present (idempotency).

4. Same exclusion rules — write to validation/excluded_remote_v2.json,
   excluded_no_source_v2.json (don't overwrite v1).

OBSERVATIONS TO RECORD
Persist to corpus/scored_code/_run_metrics.json:
- All fields from the prior _run_metrics.json schema
- prevalence_comparison: side-by-side prevalence of {tool_scope_v1,
  code_scope_v2} per category over the same 298 servers that succeeded
  in BOTH runs
- mean_breadth_tool_scope vs mean_breadth_code_scope (this drives H1)

REPORT BACK
SUMMARY
- scannable: <N>/500
- scanned succeeded: <N>
- scanned errored: <N>
- elapsed: <H>h <M>m
- peak A1 disk during run: <GB>

PREVALENCE COMPARISON (code vs tool, on 298 servers in both runs)
              tool_scope    code_scope    delta
  filesystem    4.7%          <pct>       <delta>pp
  shell        47.0%          <pct>       <delta>pp
  egress       62.8%          <pct>       <delta>pp
  ingress      27.9%          <pct>       <delta>pp
  secrets       6.0%          <pct>       <delta>pp
  delegation   18.5%          <pct>       <delta>pp
  impersonation 36.9%         <pct>       <delta>pp
  data_sens    51.3%          <pct>       <delta>pp

MEAN BREADTH (driver of H1)
- tool_scope: 2.55 categories/server (existing)
- code_scope: <X> categories/server (new)
- H1 threshold (3.0) cleared under code-scope: yes/no

PATHS
- per-server: corpus/scored_code/*.json
- run metrics: corpus/scored_code/_run_metrics.json

GIT
- branch: main
- commits: <hash> <subject>
```

### Step 3 — Compute H14 drift (small, ~30 lines of Python)

Once both scopes are scored, drift per server is a set-difference. One script writes `validation/h14_drift.json` with `{server_id, code_categories, tool_categories, drift_categories, drift_count}` per server, plus aggregate `drift_rate` (proportion with at least one drift category).

This is a simple analysis, can be done in-session or dispatched.

### Step 4 — Instrument validation (per pre-reg §4)

50-server stratified random subsample (seed `0x4d4250` per pre-reg). Hand-label the 8-category capability vector. 25-server overlap subset for Cohen's κ. Compare to extractor output for per-category precision/recall. Calibration anchors from `score_function.toml`. **No confirmatory test runs until this passes.**

### Step 5 — Confirmatory analysis

Run the 6 pre-registered tests from `docs/preregistration.md` on the code-scope corpus. All claims must hit α=0.00833 with effect-size CI.

### Step 6 — Threats-to-validity doc

Per workflow phase. `docs/threats-to-validity.md`. Required by pre-reg §5.

### Step 7 — Paper

`paper/` directory. NeurIPS LaTeX template, anonymized. Submit by May 6 AoE.

---

## Files to read first (next session)

| Priority | Path                                                            | Why                                                            |
| -------- | --------------------------------------------------------------- | -------------------------------------------------------------- |
| 1        | `CLAUDE.md`                                                     | Workflow, conventions, current-state mapping                   |
| 2        | `HANDOFF.md`                                                    | This file — orients the session                                |
| 3        | `docs/preregistration.md`                                       | The 6 confirmatory + 8 exploratory; locked design              |
| 4        | `docs/score-function.md`                                        | Now includes the "Construct" section (added in `e7e5531`)      |
| 5        | `validation/parity_check/VERDICT.md` + `_post_fix_metrics.json` | Why the construct decision was forced and proof of restoration |
| 6        | `corpus/scored/_run_metrics.json`                               | Tool-scope baseline run (the existing 298)                     |

## Memory entries (auto-loaded via `~/.claude/projects/-Users-jarvis-arunlab-code-mcp-bom/memory/MEMORY.md`)

- `project_construct_decision.md` — code-scope is canonical
- `project_storage_plan.md` — A1 drive layout
- `project_neurips_deadline.md` — May 6 AoE
- `project_corpus_archive_gap.md` — corpus history
- `feedback_research_workflow.md` — pre-registration mandatory
- `feedback_agent_push_policy.md` — agents push to main directly
- `feedback_oversight_task_format.md` — when delegating: title + 1-2 sentence what + commands + report-back only

## Latest commits on main

```
e7e5531  docs: define code-level attack surface construct in score-function.md
40978ea  test: anchor parity tests (5/5 match) + tool-scope regression + post-fix metrics
485980c  feat(extractor): restore code-scope construct, add --scope flag, re-add schema patterns
620c6b3  chore: gitignore corpus/cached + playwright, add validation set files
945efff  validation: extractor port parity check — INCONCLUSIVE
b713dab  feat(validation): precision/recall labeling pipeline with draft predictions
2ccc6ad  data(corpus): score 298/316 scannable servers with production extractor
4525946  feat(extractor): streaming corpus scan driver with rate limiting
```

## Open issues (not blockers right now)

- `#16` extractor precision/recall — addressed by Step 4 (instrument validation)
- `#17` secrets disambiguation — blocking H2/H14 confirmatory tests; resolve during Step 4
- `#18` score function sensitivity analysis — needed before paper draft
- `#19` LOC/tool-count confounder controls for H3/H5 — exploratory, can be skipped
- `#20` H12 case studies — needed for paper
- `#22` 500-corpus statistical power re-run — superseded by Step 5 confirmatory analysis

## Quality gate reminder

Before any "hypothesis supported" claim hits the paper, the 8-question gate in `CLAUDE.md` must pass: pre-registered, right statistic, multiple-comparisons-corrected p, 95% CI, effect size, confounders ruled out, instrument precision known, replicable today. If any answer is "no" — exploratory or pending, not supported.
