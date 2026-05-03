# MCP-BOM Session Handoff

> Single source of truth for picking up work between sessions. Updated 2026-05-02 — pre-reg v1.1 locked, extractor v0.2.0 with secrets disambiguation, labeling webapp deployed to forge k3s. This file lives in the repo intentionally — committed, versioned, and easy to find.

---

## ⏵ Handoff Prompt — copy-paste this to start the new session

> Paste the block below verbatim as the first message in a fresh Claude Code session at the new location. Everything the new session needs flows from there.

```
You are picking up MCP-BOM mid-flight — a NeurIPS 2026 ED Track submission
with a hard freeze of May 6, 2026 AoE.

Repo: github.com:arunsanna/mcp-bom (clone if not present)
Working directory: cd into the repo root after cloning.

Read these files FIRST, in this order, before any action or response:
  1. HANDOFF.md          — orientation, decisions, next-action sequence
  2. CLAUDE.md           — workflow, conventions, quality gate
  3. docs/preregistration.md — locked confirmatory design

After reading, do NOT start coding. Reply with:
  - One-line confirmation you've read all three
  - Which "Next actions" step you intend to execute first (likely Step 1
    if /Volumes/A1 is accessible, or report the access error if not)
  - Any blocker you noticed in the handoff that needs my attention

External storage at /Volumes/A1 (1TB) is required for the next scan.
If you cannot access /Volumes/A1, the terminal app needs Full Disk
Access in macOS System Settings → Privacy & Security, then a full
relaunch (Cmd+Q + reopen). Flag this as a blocker if you hit it.

You commit and push to main directly — no feature branches needed
(per memory feedback_agent_push_policy.md).

For any task you delegate to a sub-agent, the format is: Goal +
Implementation details + Observations to record + Report back. No
surrounding commentary in the task spec itself.

Do not relitigate the construct decision (code-level attack surface,
locked 2026-05-02). Do not modify docs/preregistration.md without
filing a deviation per its §7. Do not delete corpus/scored/ — those
298 results are the H14 tool-scope baseline cohort.
```

End of handoff prompt. Continue reading below for the project state.

---

## Project context

- **Building**: MCP-BOM, a reproducible attack-surface benchmark for MCP servers, targeting NeurIPS 2026 Evaluations & Datasets Track.
- **Hard freeze**: May 6, 2026 AoE (4 days from now).
- **Workflow**: see repo `CLAUDE.md` — code-scope construct + pre-registration + instrument validation are mandatory gates.
- **External storage**: `/Volumes/A1` (1TB HFS+, 791GB free). Verified writable from iTerm in a fresh session.

## Where we are now

| Phase                    | State                                         | Evidence                                                                              |
| ------------------------ | --------------------------------------------- | ------------------------------------------------------------------------------------- |
| Pre-registration         | locked v1.1 (anchors percentile-relative)     | `docs/preregistration.md` + `docs/preregistration-deviations.md`                      |
| Corpus manifest          | done (500 servers)                            | `corpus/manifest.json`                                                                |
| Tool-scope cohort        | preserved (H14 baseline)                      | `corpus/scored/` (298 servers, untouched)                                             |
| Code-scope cohort        | scored at extractor v0.2.0                    | `corpus/scored_code/` (298 servers + 18 errored)                                      |
| Extractor                | v0.2.0 with #17 secrets disambiguation        | `extractor/`, commit `76c9525`                                                        |
| Calibration anchors      | 3/4 verified PASS at v0.2.0                   | `validation/calibration_anchors/` (mcp-remote ASS=58.91, top decile)                  |
| Instrument-validation    | sample done (50, seed 0x4d4250); labeling IN PROGRESS via webapp | `validation/labels_arun.csv` (0/50), https://mcpbom.arunlabs.com/   |
| LLM second rater         | decision locked, not yet run                  | memory `project_labeling_decisions.md`, runs after Arun finishes labels               |
| H14 drift computation    | not started (both scopes scored, ready)       | needs `validation/h14_drift.json` from set-difference                                 |
| Confirmatory analysis    | not started (gated on labeling)               | will run with G3 sensitivity analysis baked in                                        |
| Threats-to-validity doc  | not started                                   | needs `docs/threats-to-validity.md` (Step 6)                                          |
| Paper scaffold           | not started                                   | `paper/` dir empty                                                                    |

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
4. **Pre-reg v1.1 anchors percentile-relative** (commit `62ff91e`, `docs/preregistration-deviations.md` deviation 001). Anchors tied to corpus distribution, not absolute thresholds. Reason: model ceiling at ASS≈75 made absolute ≥80 unreachable.
5. **G3 sensitivity analysis path** (Path A from manager conversation). 18 HTTPError servers stay classified as errored; Step 5 runner imputes optimistic (ASS=0) and pessimistic (ASS=max) and reports verdict robustness.
6. **LLM second rater** (memory `project_labeling_decisions.md`). Claude Sonnet 4.6 blind-labels the 25-server overlap subset for Cohen's κ. Documented as limitation in §Threats. Reason: no human second annotator available before May 6.

---

## Next actions (in order)

### Step 1 — Storage setup — DONE

Symlinks at `corpus/raw` and `corpus/cached` point to `/Volumes/A1/mcp-bom-storage/`.

### Step 2 — Code-scope re-scan — DONE

Scored at extractor v0.2.0. Results in `corpus/scored_code/` (298 succeeded + 18 errored).

### Step 3 — H14 drift computation — NOT STARTED

Set-difference between `corpus/scored/` (tool) and `corpus/scored_code/` (code). Output: `validation/h14_drift.json` with per-server `drift_categories` and aggregate `drift_rate`. Small Python script (~30 lines).

### Step 4 — Instrument validation — IN PROGRESS

- Sample done: `validation/instrument_validation_set.json` (50 servers, seed `0x4d4250`)
- Labeling webapp deployed: https://mcpbom.arunlabs.com/
- Arun labels 50 servers via webapp (MB-008 in AI Memory)
- When labels exported back to `validation/labels_arun.csv`, dispatch Task #10: LLM second rater + per-category precision/recall + Cohen's κ

### Step 5 — Confirmatory analysis — gated on Step 4

6 pre-registered tests + G3 sensitivity analysis (impute 18 errored both ways, report verdict robustness).

### Step 6 — Threats-to-validity doc — can start in parallel

`docs/threats-to-validity.md` per pre-reg §5 + new threats (anchor recalibration discovery, LLM-as-rater limitation, G3 imputation sensitivity).

### Step 7 — Paper — `paper/` dir, NeurIPS LaTeX, anonymized. Submit by May 6 AoE.

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
| 7        | `docs/preregistration-deviations.md`                            | What changed in v1.1 and why                                   |
| 8        | `memory/project_labeling_decisions.md`                          | Locked LLM-second-rater + blind-labeling decisions             |
| 9        | `validation/calibration_anchors/manifest.json`                  | All 3 anchor results at v0.2.0                                 |
| 10       | `labeler/`                                                      | Web labeling helper source (deployed to forge k3s)             |

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
f4c51de fix(labeler): use istio VirtualService instead of traefik IngressRoute
b94705c feat(labeler): web labeling helper for instrument-validation phase (deployed to forge k3s)
c66d51c validation: re-run mcp-remote calibration anchor with extractor v0.2.0 (parity with corpus)
3efcd57 data(corpus): re-score 316 servers with v0.2.0 extractor (post-#17 disambiguation)
76c9525 fix(extractor): disambiguate config-only env reads from secrets (closes #17, bump v0.2.0)
4f2fee3 validation: add mcp-remote calibration anchor (CVE-2025-6514, pre-reg v1.1 §4)
62ff91e docs: pre-reg v1.1 -- recalibrate §4 anchors to percentile-relative (deviation 001)
d53f53c data(corpus): score 316 scannable servers with --scope code (H1/H4/H14 input)
e8f938a validation: stratified 50-server instrument-validation sample (seed 0x4d4250, source-stratified per pre-reg §4)
59de2f1 chore(gitignore): match corpus/raw and corpus/cached symlinks (drop trailing slash)
71e17cd docs(handoff): add copy-pasteable prompt block at top
5a7ac87 docs: HANDOFF — final, code-scope restored, ready for code-scope re-scan
e7e5531 docs: define code-level attack surface construct in score-function.md
40978ea test: anchor parity tests (5/5 match) + tool-scope regression + post-fix metrics
485980c feat(extractor): restore code-scope construct, add --scope flag, re-add schema patterns
```

## Open issues (not blockers right now)

- `#16` extractor precision/recall — in progress via Task #4 sample + forthcoming Task #10 LLM rater eval
- `#17` ~~secrets disambiguation~~ — **closed** by commits `76c9525` + `3efcd57`
- `#18` score function sensitivity analysis — needed before paper draft
- `#19` LOC/tool-count confounder controls for H3/H5 — exploratory, can be skipped
- `#20` H12 case studies — needed for paper
- `#22` 500-corpus statistical power re-run — code-scope re-scan done (commit `3efcd57`); confirmatory tests still pending (Step 5)

## Quality gate reminder

Before any "hypothesis supported" claim hits the paper, the 8-question gate in `CLAUDE.md` must pass: pre-registered, right statistic, multiple-comparisons-corrected p, 95% CI, effect size, confounders ruled out, instrument precision known, replicable today. If any answer is "no" — exploratory or pending, not supported.
