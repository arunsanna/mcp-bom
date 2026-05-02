# MCP-BOM Pre-Registration v1

> Locked design specification for the MCP-BOM confirmatory analysis. Written **before** running the extractor on the 500-server corpus. Per repo `CLAUDE.md`, this document gates any "hypothesis supported" claim in the paper. Deviations from this document must be enumerated in a "Deviations from Pre-registration" subsection of the paper.

| Field                               | Value                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------ |
| Pre-registration date               | 2026-05-01                                                               |
| Pre-registration version            | v1.1 (amended 2026-05-02; original v1 locked 2026-05-01)                |
| Corpus snapshot                     | `corpus/manifest.json` (500 servers, snapshot 2026-05-01)                |
| Score function version              | `score_function.toml` v1 (locked)                                        |
| Taxonomy version                    | `docs/capability-taxonomy.md` v1 (locked)                                |
| Confirmatory hypothesis family size | 6                                                                        |
| Family-wise α                       | Bonferroni 0.05 / 6 = **0.00833** (BH-FDR q=0.05 reported as robustness) |

---

## 1. Confirmatory Hypotheses

Each confirmatory hypothesis below specifies: operational definition, null and alternative, test statistic, "supported" threshold, and pre-declared confounder controls. A claim of "supported" in the paper requires **all** of: (a) the directional inequality, (b) p < 0.00833, (c) the 95% bootstrap CI on the effect excluding the null value.

### H1 — Capability Sprawl

> The average MCP server exposes capabilities across more than 3 of the 8 taxonomy categories.

- **Operational metric**: `n_categories_detected` per server (integer in [0, 8]) from extractor output.
- **H0**: μ ≤ 3.0
- **H1**: μ > 3.0
- **Test**: one-sample t-test on `n_categories_detected` against 3.0. Robustness: Wilcoxon signed-rank if Shapiro–Wilk rejects normality at α=0.05.
- **Effect size**: (μ − 3.0) with 10k-resample bootstrap 95% CI.
- **Supported iff**: lower bound of bootstrap CI > 3.0 AND p < 0.00833.
- **Threats**: detection FP inflates μ. Mitigated by instrument validation (§4) — categories with precision < 0.7 are excluded from this count.

### H2 — Secrets Gateway (revised)

> Servers with secrets access exhibit attack-surface scores at least 2× higher than servers without, and the effect persists after controlling for total capability count.

- **Operational metric**: `ASS` score per server. `secrets_detected` is the binary indicator from the extractor **after issue #17 resolution** — config-only secrets reads (e.g., `os.getenv("PORT")`) are excluded; only exposed-capability secrets reads count.
- **H0**: ratio of geometric mean ASS (secrets / no-secrets) ≤ 2.0
- **H1**: ratio > 2.0
- **Test**: Welch's t-test on `log(ASS + 1)`. Bootstrap of geometric-mean ratio (10k resamples) for CI.
- **Confounder control (mandatory)**: linear regression `ASS ~ secrets + n_categories + language + source_tier`. The `secrets` coefficient must remain positive and significant at α=0.00833.
- **Effect size**: log-ratio with 95% CI; standardized regression coefficient.
- **Supported iff**: (a) ratio CI lower bound > 2.0, (b) Welch's p < 0.00833, **AND** (c) secrets coefficient in controlled regression p < 0.00833.

### H4 — Ingress Risk Multiplier (de-tautologized)

> Servers exposing network ingress bundle more high-risk capabilities (excluding ingress itself) than non-ingress servers.

- **Why revised**: the original H4 ("ingress predicts higher ASS") is partially tautological because the score function rewards ingress in both depth and exposure components. The revised hypothesis tests a non-tautological capability-vector claim.
- **Operational metric**: `breadth_excl_ingress` = count of detected categories from {filesystem, shell, egress, secrets, delegation, impersonation, data_sensitivity} per server.
- **H0**: μ*{breadth_excl_ingress | ingress=Y} ≤ μ*{breadth_excl_ingress | ingress=N}
- **H1**: strictly greater
- **Test**: Welch's t-test. Robustness: Mann–Whitney U.
- **Confounder control**: report regression `breadth_excl_ingress ~ ingress + source_tier + language` to rule out tier confound.
- **Effect size**: Cohen's d with bootstrap CI.
- **Supported iff**: d ≥ 0.5, p < 0.00833, ingress coefficient remains positive significant after tier control.

### H5 — Super-Linear Inverted Boundary

> The combination of network ingress and inter-server delegation produces an interaction effect on attack surface beyond the sum of their independent contributions.

- **Operational metric**: 2×2 design — `ingress` × `delegation`. Outcome: `ASS` and (separately) `breadth_excl_ingress_and_delegation`.
- **H0**: interaction coefficient β\_{ingress × delegation} ≤ 0
- **H1**: β > 0
- **Test**: two-way ANOVA with interaction term. Primary outcome: `breadth_excl_ingress_and_delegation` (the non-tautological version). Secondary outcome: `ASS` (reported with caveat).
- **Effect size**: η² for interaction term.
- **Supported iff**: interaction coefficient positive in primary outcome, p < 0.00833, and 95% CI excludes 0. Secondary `ASS` outcome reported as supplementary.

### H12 — CWE / MCP-BOM Complementarity (reframed)

> Traditional CWE-based vulnerability counts (Semgrep) and MCP-BOM attack-surface scores measure complementary, not redundant, risk dimensions.

- **Why reframed (per issue #23)**: original H12 ("orthogonality") is too strong; observed |r| ≈ 0.15 in spike supports "small overlap" rather than "no overlap." Reframe to "complementarity" with a TOST-style equivalence test.
- **Operational metrics**: `ASS` per server; `cwe_finding_count` per server from Semgrep on a 50-server stratified random subset (sampled with seed 0x4d435042 = "MCPB" before any analysis).
- **H0**: |Pearson r(ASS, cwe_finding_count)| ≥ 0.5
- **H1**: |r| < 0.5 (substantial complementarity)
- **Test**: Pearson r with Fisher-z 95% CI. Robustness: Spearman ρ. Equivalence framing: TOST with bounds [−0.5, +0.5].
- **Supported iff**: 95% CI upper bound on |r| < 0.5 AND TOST p < 0.00833.
- **Threats**: Semgrep ruleset coverage matters — pre-declare ruleset version (`p/security-audit` + `p/owasp-top-ten`).

### H14 — Schema vs Implementation Drift

> Over 20% of MCP servers contain capabilities in their source code that are not declared in their `tools/list` JSON schema.

- **Operational metric**: `has_drift` per server — true iff `(impl_detected_categories \ schema_declared_categories) ≠ ∅`. **After issue #17 resolution**: drift entries that consist solely of config-only secrets are excluded.
- **Sample frame**: subset of 500 corpus where the extractor produces both a non-empty `schema_declared_categories` AND a non-empty `impl_detected_categories`. Servers below either threshold are reported separately.
- **H0**: drift_rate ≤ 0.20
- **H1**: drift_rate > 0.20
- **Test**: one-sample binomial test against 0.20. Wilson score 95% CI on the proportion.
- **Supported iff**: lower bound of Wilson CI > 0.20, p < 0.00833.
- **Spike anchor**: spike v3 showed ~64% drift before #17 resolution; expect deflation but well above threshold.

---

## 2. Exploratory Hypotheses (no α gate)

The following are reported in the paper as **exploratory** — findings will not be claimed as "confirmed" regardless of p-value. Reported with effect size and CI for transparency, but excluded from the family-wise correction.

| H                                         | Status                                                | Reason exploratory                                                               |
| ----------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------- |
| H3 — TS > Python                          | confounded with source-tier                           | Cannot disentangle language from tier without stratified subsample we don't have |
| H6 — Co-location PMI (secrets/db × shell) | n too small for stable PMI                            | Report PMI with bootstrap CI, no claim                                           |
| H7 — Lookalike risk premium               | detector noise (267 lookalikes / 245 corpus in spike) | Detector requires audit before any claim                                         |
| H8 — Registry governance variance         | sample frame imbalance                                | npm/PyPI dominate; community-only sample is small                                |
| H9 — Stale server decay                   | sign flipped in spike (post-hoc reformulation)        | HARKing risk if claimed; reported as observation                                 |
| H10 — Approval gate prevalence            | n=4 impersonation servers in spike                    | Even with full corpus, impersonation count likely < 30                           |
| H11 — God-mode DB default                 | detector too narrow                                   | Manual review of subset will be reported as exploratory                          |
| H13 — Safe-language fallacy               | Go/Rust sample insufficient even in 500 corpus        | Report descriptive only                                                          |

---

## 3. Sample, Exclusions, Stopping Rule

### Sample frame

- **All confirmatory tests run on `corpus/manifest.json`** (500 servers, snapshot 2026-05-01). No interim peeking; no addition or removal of servers from the manifest after this pre-registration is committed.
- **H12** uses a stratified random subsample of 50 servers (10 per source × 5 sources) drawn with deterministic seed `0x4d435042` BEFORE any Semgrep run.

### Pre-declared exclusions

- Servers with no fetchable source archive (registry stub only) — excluded from extractor-dependent tests; counted in `validation/excluded_no_source.json`.
- Servers where the extractor raises an exception — excluded; logged in `validation/extractor_errors.json`. If exclusion rate > 5%, the result section must report sensitivity analysis with errored servers imputed both ways.
- Same upstream repo across registries — collapsed to one canonical entry by `(github_owner, github_repo)`. Duplicates reported as a separate descriptive table.
- Test/example servers (the README or `package.json` description matches `/test|example|playground|sample/i`) — included with `tier=test`. Sensitivity analysis: re-run all confirmatory tests with `tier=test` excluded; report only if any verdict flips.

### Stopping rule

- Run extractor on all 500 in one pass. **No interim look at confirmatory test outcomes.** If the extractor errors on > 5% of the corpus, halt and fix before any test is run.
- If instrument validation (§4) shows precision < 0.7 for a category, the confirmatory tests that depend on that category are halted; detector is fixed; full corpus is re-run from scratch with a version bump (`v1.1`) and a new pre-registration addendum noting the change.

---

## 4. Instrument Validation (must precede confirmatory analysis)

Per repo `CLAUDE.md`, no confirmatory test runs until the measurement instrument is validated.

- **Ground truth set**: 50 servers, stratified random sample from the 500 corpus (different seed: `0x4d4250` = "MBP"). One annotator (Arun) hand-labels the 8-category capability vector. A second annotator labels 25 of the 50 (overlap subset) for inter-rater reliability.
- **Per-category precision and recall** reported in `validation/extractor_metrics.json`. Each value with 95% Wilson CI.
- **Cohen's κ** on the 25-server overlap subset. Target ≥ 0.6 (substantial agreement). Below 0.4 (fair) halts the run.
- **Calibration anchors (v1.1, percentile-relative)**:
  Computed against the corpus snapshot 2026-05-01 (n=298 successfully
  scored servers, code-scope, in `corpus/scored_code/`). Percentiles
  refer to the ASS distribution of that scored set.

  - CVE-2025-6514 (`mcp-remote`) — known-vulnerable remote-access
    proxy. Out-of-corpus anchor (not in the 500 manifest).
    Required ASS ≥ p50 of corpus (≈ 31.61 ASS). Tested separately
    in `validation/calibration_anchors/` (TBD task).
  - CVE-2025-49596 (MCP Inspector CSRF→RCE) — known-vulnerable.
    In-corpus anchor (`npm-modelcontextprotocol-inspector`).
    Required ASS ≥ p50 of corpus (≈ 31.61). Observed: 41.28
    (≈ p70). PASSES.
  - Localhost-only filesystem-read-only with active maintenance
    — narrow-surface floor anchor. Required ASS ≤ p33 of corpus
    (≈ 23.22). In-corpus example: `pypi-mcp-server-sqlite` at
    16.22. PASSES.
  - Public-no-auth ingress + direct shell — worst-case ceiling
    anchor. Required ASS ≥ p90 of corpus (≈ 55.22). If no such
    server exists in the corpus, the anchor is documented as
    untestable and reported as a §5 construct-validity threat.
- **If any percentile-relative anchor fails**: investigate root cause
  first. (a) If extractor bug — bounded fix, re-score affected
  servers, re-check anchor. No pre-reg amendment. (b) If score-
  function structural issue — weight re-tune triggers a v1.1 → v1.2
  amendment per §7 and the §1 confirmatory family is re-run on the
  re-scored corpus. (c) If the anchor selection itself is flawed
  (e.g., set above the model's mathematical ceiling) — document as
  a §7 deviation, do NOT re-tune the model to satisfy a flawed anchor.

---

## 5. Pre-Declared Threats to Validity

Listed here so the paper's Threats-to-Validity section cannot omit them.

### Internal validity

- **Tautology risk** in original H4 / H5 — addressed by revised operationalizations on capability-vector metrics excluding ingress and delegation.
- **Confounding** in H2 (secrets vs total capability count), H4 (ingress vs server tier), H5 (interaction vs main effects) — addressed by mandatory regression controls.
- **Detector precision** as a confounder for every category-based claim — addressed by §4 instrument validation gate.

### External validity

- **Sample frame** is "popular MCP servers across 5 registries snapshotted 2026-05-01," not "all MCP servers." Findings generalize to in-use servers, not to long-tail community ones.
- **Snapshot date** — May 2026 ecosystem state. MCP is rapidly evolving; replication on a future snapshot may show drift.
- **Language coverage** — extractor v1 is Python + TypeScript + Go (basic). Rust / Java MCP servers may be under-detected.

### Construct validity

- **ASS measures declared and detected capability scope, not exploited attack surface.** Dynamic testing is deferred to camera-ready.
- **OWASP Agentic Top 10 severity weights** are consensus-derived, not empirically derived. Sensitivity analysis (issue #18) reports verdict stability under ±20% weight perturbation; results section must include the sensitivity table.

### Conclusion validity

- **Multiple comparisons** — addressed by Bonferroni at 0.00833 with BH-FDR robustness.
- **Statistical power** — n=500 gives > 95% power for all confirmatory tests at the spike-observed effect sizes; pre-registered effect-size thresholds chosen so reported "supported" verdicts correspond to practically meaningful effects, not just statistically detectable ones.
- **Non-independence** — same upstream repo across registries violates independence; collapsed by canonical-repo deduplication before testing.

---

## 6. Locked Operational Definitions

Bound by this pre-registration; cannot be changed without versioning the doc.

- **`n_categories_detected`**: count of categories with extractor confidence ≥ medium AND post-#17 disambiguation applied (config-only secrets do not count toward `secrets`).
- **`ASS`**: score from `score_function.toml` v1 weights, no per-run re-tuning except per §4 anchor failure.
- **`has_drift`**: defined in §H14.
- **`canonical-repo deduplication`**: collapse by `(github_owner.lower(), github_repo.lower())`. If no GitHub URL, treat as canonical.
- **`source_tier`**: `official` (npm `@modelcontextprotocol`, official MCP Registry), `enterprise` (Anthropic, Cloudflare, OpenAI, Microsoft, Google, AWS, Stripe, Linear, Notion, Slack, Sentry, Cloudflare, Supabase, Neon, etc. — full list locked in `corpus/tier_assignments.json`), `community` (everything else). Tier locked at corpus snapshot time; not re-derived.
- **Bootstrap**: 10,000 resamples with replacement, stratified by source if applicable, seed `0x4d4350` = "MCP".

---

## 7. Deviation Policy

If reality forces a change to this pre-registration after analysis begins:

1. The change is documented in `docs/preregistration-deviations.md` with: what changed, why, when (UTC timestamp), and the git hash of this file at the time of the change.
2. Any confirmatory test affected is reclassified as exploratory in the paper.
3. The "Deviations from Pre-registration" subsection of the paper enumerates each change.
4. If the change is substantive (new test, new exclusion), a `v1.1` is created and the affected tests re-run on the full corpus.

---

## 8. Locked git hash

This pre-registration takes effect at the commit that introduces this file. Subsequent edits update the version field above and add an entry to `docs/preregistration-deviations.md`.
