# MCP-BOM — Repo Operating Instructions

## Project

MCP-BOM is a reproducible attack-surface benchmark for Model Context Protocol (MCP) servers. Two deliverables: (1) an 8-category permission **taxonomy**, (2) a 0–100 numeric **score function** derived from OWASP Agentic Top 10 severity. Targeting **NeurIPS 2026 Evaluations & Datasets Track**.

- **Hard freeze**: May 6, 2026 AoE
- **Author**: Arun Chowdary Sanna
- **Work board**: GitHub Issues + AI Memory project `mcp-bom`
- **Build plan**: `docs/build-plan.md`

---

## Empirical Research Workflow (canonical)

This repo follows the rigorous version of the empirical-research workflow. Apply it to every hypothesis-driven claim. The discovery loop is necessary but not sufficient — the four extra phases (pre-registration, instrument validation, threats-to-validity, internal peer review) turn signals into defended claims.

```
Prior art / RQ formulation
   ↓
Hypotheses (operational definitions, falsifiable)
   ↓
Spike (cheap, exploratory — n small, fast iteration)
   ↓
Observation (capture findings, mark exploratory revisions)
   ↓
PRE-REGISTRATION  ← lock design BEFORE confirmatory data
   ↓
Confirmatory experiment on FRESH sample
   ↓
Validation of instrument  ← precision/recall, inter-rater κ, calibration
   ↓
Eval observations  ← CI, p-value, effect size, multiple-comparisons correction
   ↓
Compare to prior art  ← head-to-head empirical, not just narrative
   ↓
Threats to validity  ← internal / external / construct / conclusion
   ↓
Reproducibility artifacts  ← code, data, metadata, checklist
   ↓
Internal peer review  ← paperreview.ai + colleague
   ↓
Publish
   ↓
Feedback & improve  ← responsible disclosure, replication, camera-ready
```

Full reference saved to wiki: `wiki://inbox/2026-05-01T210202Z__empirical-research-workflow-hypothesis-to-publish.md`.

### Phase rules

- **Pre-registration is non-optional** for any tested hypothesis. Write `docs/preregistration.md` BEFORE running on the full corpus. Specify exact tests, α (Bonferroni- or BH-corrected for the hypothesis family), n (from power analysis), exclusion criteria, stopping rule. Mark hypotheses confirmatory vs exploratory.
- **Instrument validation is non-optional** when using a custom-built measurement tool (extractor, scorer, classifier). Report precision/recall on a labeled ground-truth subset. Report Cohen's κ for taxonomy assignments (target ≥ 0.6).
- **Eval reports must include**: 95% CIs (bootstrap with ≥10k resamples for small n), effect sizes (Cohen's d / Cliff's delta), and the multiple-comparisons-corrected p-value. Means and ratios alone are not findings.
- **Compare to prior art means head-to-head**: run MCP-in-SoS, Snyk, or any baseline on the SAME servers and report what each catches that the other misses. Narrative differentiation in Related Work is necessary but not sufficient.
- **Threats-to-validity is a phase, not a footnote**: write `docs/threats-to-validity.md` covering internal (confounders), external (sample bias), construct (does the metric capture the concept?), conclusion (statistical power).
- **Feedback loop is real**: post-submission, run responsible disclosure to top-N highest-score maintainers (issue #14), use reviewer comments to harden v2.

### Failure modes to catch (and the phase that catches each)

| Failure              | Symptom                                                          | Caught by                               |
| -------------------- | ---------------------------------------------------------------- | --------------------------------------- |
| HARKing              | Hypothesis revised after seeing data                             | Pre-registration                        |
| Tautology            | Score function rewards X, then "X correlates with score" claimed | Pre-registration + Threats-to-validity  |
| Underpowered claim   | "Supported" with n=10 and no p-value                             | Power analysis in pre-registration      |
| Confounded variable  | Language effect that's actually a tier effect                    | Threats-to-validity                     |
| Instrument noise     | 267 lookalikes flagged in 245-server corpus                      | Validation of instrument                |
| Multiple comparisons | 14 hypotheses, all "supported" at α=0.05                         | Bonferroni / BH-FDR in pre-registration |
| Selection bias       | Convenience sample of popular servers                            | Threats-to-validity (external)          |

---

## Current state mapping

| Phase                     | Status                                        | Artifact                                                                           |
| ------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------- |
| Prior art / RQ            | done                                          | `docs/prior-art-assessment.md`, `docs/research-design.md`                          |
| Hypotheses                | done (14)                                     | `docs/extended-hypotheses.md`                                                      |
| Spike                     | 3 rounds done (n=23→27, 245 scraped)          | `spike/run_spike.py`, `run_spike_v2.py`, `run_spike_v3.py`, `spike/results/*.json` |
| Observation               | partial — v2 written, **v3 markdown missing** | `spike/results/hypothesis_validation_v2.md`                                        |
| Pre-registration          | **v1 locked** (2026-05-01)                    | `docs/preregistration.md` — 6 confirmatory + 8 exploratory; α=0.00833              |
| Confirmatory experiment   | not started                                   | needs production extractor + 500-server corpus                                     |
| Instrument validation     | not started                                   | needs `validation/` work (precision/recall + Cohen's κ)                            |
| Eval observations         | informal only                                 | needs proper stats                                                                 |
| Compare                   | narrative only                                | needs head-to-head with MCP-in-SoS                                                 |
| Threats-to-validity       | not written                                   | needs `docs/threats-to-validity.md`                                                |
| Reproducibility artifacts | not started                                   | anonymized repo, HF dataset, Croissant metadata                                    |
| Internal peer review      | not run                                       | issue #12 (paperreview.ai)                                                         |
| Publish                   | not started                                   | `paper/` dir empty                                                                 |
| Feedback & improve        | future                                        | issues #14, #15                                                                    |

---

## Conventions

- **Scope discipline**: don't refactor, polish, or expand beyond the task. Bug fixes get bug fixes; the surrounding cleanup is a separate ask.
- **Stats hygiene**: never report a group difference without a CI and an effect size. Never report a "supported" hypothesis without the test that supports it.
- **Spike vs production**: code in `spike/` is exploratory (one-shot, hand-edited OK). Code in `extractor/` and `validation/` is production (typed, tested, reproducible). Don't blur the line.
- **Construct disambiguation**: when defining a detector (e.g., "secrets"), distinguish config reads from exposed-capability reads. False positives compound — see issue #17.
- **Locked artifacts**: `score_function.toml` and `docs/capability-taxonomy.md` are locked v1. Changes require a version bump and a documented rationale.

---

## Quality gate before claiming any hypothesis is supported

1. Pre-registered? (yes/no — if no, mark exploratory)
2. Tested with the right statistic? (Welch's t / Mann-Whitney / PMI / χ² / Pearson — name it)
3. p-value with multiple-comparisons correction reported?
4. 95% CI on the effect reported?
5. Effect size (Cohen's d / Cliff's δ) reported?
6. Confounders ruled out or named as threat-to-validity?
7. Instrument precision/recall known?
8. Replication possible from the repo as it stands today?

If any answer is "no," the claim is exploratory or pending — not supported.

---

## Pointers

- Build plan: `docs/build-plan.md`
- NeurIPS strategy: `docs/neurips-strategy.md`
- Score function spec: `docs/score-function.md` + `score_function.toml`
- Capability taxonomy: `docs/capability-taxonomy.md`
- Hypotheses: `docs/extended-hypotheses.md`
- Spike data: `spike/results/spike_v3_results.json`
- Open work: `gh issue list --repo arunsanna/mcp-bom`
- Workflow reference: `wiki://inbox/2026-05-01T210202Z__empirical-research-workflow-hypothesis-to-publish.md`
