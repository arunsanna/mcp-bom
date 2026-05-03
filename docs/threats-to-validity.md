# MCP-BOM Threats to Validity

> Companion to `docs/preregistration.md` §5. Each threat below specifies
> magnitude (or how it is bounded), direction of bias (which way it would
> push verdicts), mitigation (what we did about it), and residual risk
> (what remains uncontrolled). Threats labelled **NEW** were discovered
> during Tasks #1–#11 and were not in the original pre-registration.

---

## Internal validity

### IV-1. Tautology in original H4 / H5 (pre-reg)

The original formulations of H4 ("ingress predicts higher ASS") and H5
("ingress × delegation interaction on ASS") were partially tautological
because the score function rewards ingress directly in both the depth
component (ingress depth up to 10) and the exposure component (public
bind scores up to 100). Discovering that a predictor is part of the
outcome is the classic tautology threat. **Mitigation**: H4 and H5
were revised to use capability-vector outcomes (`breadth_excl_ingress`
and `breadth_excl_ingress_and_delegation`) that exclude the predictor
categories, de-tautologising the hypothesis (pre-reg v1.1 §H4, §H5).
**Residual risk**: secondary ASS-based outcomes for H5 are still
reported as supplementary material, with an explicit caveat that ASS
is a partially tautological outcome for these two hypotheses.

### IV-2. Confounding in H2 — secrets × total capability count (pre-reg)

Servers that read secrets may systematically differ from those that do
not along several axes: they may be more feature-rich (higher total
capability count), come from different source tiers, or be written in
different languages. Any of these could confound the secrets-vs-ASS
comparison. **Mitigation**: the confirmatory test for H2 requires a
controlled regression `ASS ~ secrets + n_categories + language +
source_tier`, and the secrets coefficient must remain positive and
significant at α = 0.00833 for the hypothesis to be supported.
**Residual risk**: unmeasured confounders (e.g., organisational
maturity, deployment model) are not captured in the extractor output
and remain uncontrolled.

### IV-3. Confounding in H4 — ingress vs source tier (pre-reg)

Ingress-exposing servers may cluster in higher-tier sources
(enterprise, official), which themselves correlate with different
development practices and capability profiles. **Mitigation**: the
confirmatory regression `breadth_excl_ingress ~ ingress + source_tier
+ language` is required, and the ingress coefficient must remain
positive and significant after tier control. **Residual risk**: tier
is a coarse three-level variable and may not capture fine-grained
quality differences within tiers.

### IV-4. Detector precision as confounder for category-based claims (pre-reg)

Every hypothesis that uses detected/not-detected category membership
(H1, H2, H4, H5, H14) depends on the extractor's per-category
precision. Systematic false positives inflate capability breadth and
prevalence; false negatives deflate them. **Direction**: FP inflation
would bias toward supporting H1 (capability sprawl), H2 (secrets
gateway), and H14 (schema drift). **Mitigation**: §4 of the
pre-registration gates confirmatory analysis on instrument validation;
categories with precision < 0.7 on the 50-server ground-truth set are
excluded from `n_categories_detected` for H1. Per-category
precision/recall with 95% Wilson CIs are reported in
`validation/extractor_metrics.json`. **Residual risk**: the 50-server
ground-truth set is itself labelled by the taxonomy author (see CV-4);
residual misclassification propagates to all category-based claims.

### IV-5. Issue #17 disambiguation finding (NEW)

The initial hypothesis during spike v3 was that the high secrets
prevalence (78.5% under extractor v0.1.0) was driven by false
positives from conflation of config-only environment reads (e.g.,
`os.getenv("PORT")`, `os.getenv("HOST")`) with capability-secrets
reads (e.g., `os.getenv("API_KEY")`). Task #7 implemented a classifier
to disambiguate config-only from exposed-capability secrets reads.
Post-fix prevalence: **78.9%** — essentially unchanged. The FP
hypothesis was partially wrong: most servers that read at least one
config-only env var also read at least one genuine secret env var.
**Direction of pre-fix bias**: would have inflated category breadth
for servers that read only config env vars (counting them as
secrets-capable when they were not). **Mitigation**: extractor v0.2.0
includes the disambiguating classifier; the corpus was fully re-scored
with v0.2.0 (corpus/scored_code/_run_metrics.json confirms extractor
version 0.2.0). **Residual risk**: the classifier's own precision
awaits final validation in Task #10; the 78.9% prevalence may be a
genuine ecosystem signal but could still include residual
misclassification.

---

## External validity

### EV-1. Sample frame — popular MCP servers, 5 registries, snapshot 2026-05-01 (pre-reg)

The corpus is drawn from five registries (npm, PyPI, Smithery, the
official MCP Registry, and GitHub search) with a popularity filter
applied at manifest-assembly time. This is a sample of **in-use,
discoverable MCP servers**, not a random sample of all MCP servers in
existence. Long-tail community servers, private enterprise deployments,
and servers published after the snapshot date are excluded.
**Magnitude**: the 500-server corpus represents the most-installed and
most-starred servers as of May 1, 2026; findings generalise to the
population of actively-maintained, publicly-available servers.
**Direction**: popular servers may be better-maintained (biasing
prevalence downward) or more feature-rich (biasing prevalence upward);
the net direction is unknown. **Residual risk**: findings may not
generalise to niche or private MCP servers.

### EV-2. Snapshot date — May 2026 ecosystem state (pre-reg)

MCP is a rapidly evolving protocol; the ecosystem is expanding rapidly.
The snapshot was taken on 2026-05-01; 18 of the 500 manifest entries
returned HTTP 404 errors one day after snapshot during scanning on
2026-05-02 (3.6% immediate attrition). **Magnitude**: any replication
attempted on a future date will see further drift as servers are
renamed, moved, or deleted. **Mitigation**: all successfully downloaded
archives are preserved locally; the scorer is a pure function of the
archive contents, enabling deterministic re-scoring. **Residual risk**:
the ecosystem-state threat is irreducible — the paper reports findings
for one snapshot and acknowledges temporal fragility.

### EV-3. Language coverage — Python + TypeScript + Go basic (pre-reg)

Extractor v0.2.0 detection patterns are strongest for Python and
TypeScript/JavaScript, basic for Go, and absent for Rust, Java, and
other languages. The corpus includes servers written in languages
beyond the extractor's pattern coverage. **Direction**: servers in
under-detected languages will have deflated capability breadth and ASS,
biasing prevalence estimates downward. **Mitigation**: language is
recorded per server and included as a covariate in controlled
regressions (H2, H4); the paper reports language distribution and flags
this threat explicitly. **Residual risk**: any claim about the "average
MCP server" is conditional on the language mix in the corpus; the
claim does not extend to servers in unpatterned languages.

### EV-4. Corpus snapshot fragility (NEW)

Beyond the 18 servers that returned HTTP errors (see CnV-4), the
corpus manifest includes 181 servers that were pre-filtered as
remote-only (no fetchable source) and 3 with no source at all. The
scannable set was 316 of 500 manifest entries. **Direction**: the
excluded servers may differ systematically from the scanned set — if
remote-only servers are more likely to be lightweight wrappers, their
exclusion inflates capability prevalence. **Mitigation**: excluded
servers are enumerated in `validation/excluded_remote_v2.json` and
`validation/excluded_no_source_v2.json`; exclusion rates and counts
are reported in the paper. Calibration anchors use pinned tarball
SHAs (calibration_anchors/manifest.json model) where available. Raw
archives are kept on local storage (`/Volumes/A1/mcp-bom-storage/`)
for future replication. **Residual risk**: the 184 excluded servers
(36.8% of manifest) represent a meaningful gap; the paper's claims are
explicitly scoped to the 316-server scannable set and the 298-server
successfully-scored subset.

---

## Construct validity

### CV-1. ASS measures declared + detected capability scope, not exploited attack surface (pre-reg)

ASS is a static analysis metric: it measures the breadth and depth of
capabilities present in server source code, not whether those
capabilities have been or can be exploited. A server with a high ASS
has a *wider* attack surface, not necessarily a *worse* security
posture. **Mitigation**: calibration anchors include CVE-known
vulnerable servers; the MCP Inspector (CVE-2025-49596, CSRF→RCE) ranks
at p70 of the corpus (ASS = 41.28), which is consistent with its
known vulnerability severity within the relative ranking. Dynamic
exploit testing is deferred to camera-ready. **Residual risk**: ASS
should be interpreted as a relative risk ranking, not an absolute
measure of exploitability.

### CV-2. OWASP Agentic Top 10 weights are consensus-derived (pre-reg)

The score function's weights (depth = 0.45, breadth = 0.20, exposure =
0.20, provenance = 0.15) and per-category depth values are derived
from the OWASP Agentic Top 10 (2026) severity rankings, which are
expert-consensus-derived rather than empirically calibrated. Different
weight choices would produce different ASS distributions and potentially
different hypothesis verdicts. **Mitigation**: issue #18 will run a
sensitivity analysis under ±20% weight perturbation; the results
section must include a sensitivity table showing verdict stability.
**Residual risk**: until the sensitivity analysis is completed, the
degree to which verdicts depend on specific weight choices is unknown.

### CV-3. Anchor mathematical ceiling (NEW)

Task #5 diagnostics revealed that the score function's weight structure
caps ASS at approximately 75 for real servers (corpus max: 74.9). The
original calibration anchors of ASS ≥ 80 and ≥ 90 were mathematically
unreachable. This is not an extractor bug but a structural property of
the weight model: depth is weighted at 0.45 but even a server with
all eight categories at maximum depth (80 raw depth points) and
maximum exposure (100) and worst provenance (100) cannot reach 100
because breadth (8/8 = 100) is weighted only 0.20 and the depth
normalisation denominator (80) caps the depth contribution. **Magnitude**:
the ceiling affects interpretation of ASS as an absolute metric.
**Mitigation**: pre-registration deviation 001 recalibrated all anchors
to percentile-relative thresholds (p50, p33, p90 of the observed
distribution). ASS is now explicitly framed as a **relative risk
ranking within the MCP ecosystem**, not an absolute risk percentage.
**Residual risk**: readers may still interpret ASS values on a 0–100
scale as percentage-like; the paper must prominently state the
relative interpretation. Future work should consider re-tuning the
weight structure for better dynamic range, but doing so on the
confirmatory corpus would constitute HARKing.

### CV-4. Single-annotator bias for the taxonomy itself (NEW)

Arun is both the taxonomy author (`docs/capability-taxonomy.md`) and
the sole human annotator for the 50-server instrument-validation
ground-truth set (`validation/labels_arun.csv`). This creates a
confirmation-bias risk: Arun's labels may reflect his own categorisation
rationale rather than independent judgment. If the extractor was built
to match the same rationale, the entire validation loop becomes
partially circular. **Direction**: bias would inflate measured precision
and recall of the extractor (if the extractor and the annotator share
the same heuristics), and inflate Cohen's κ (if the LLM second rater
also aligns). **Mitigation**: (a) blind labeling — Arun labeled
without peeking at extractor output, using only raw source archives via
the labeling webapp; (b) LLM second rater on the 25-server overlap
subset, also blind to extractor output (see CnV-5); (c) raw labels
published in `validation/labels_arun.csv` for reviewer audit.
**Residual risk**: meaningful. The taxonomy itself reflects one
researcher's mental model of MCP capabilities. No independent taxonomy
development was conducted. Reviewers can assess the taxonomy's
face validity from `docs/capability-taxonomy.md`.

---

## Conclusion validity

### CnV-1. Multiple comparisons (pre-reg)

Six confirmatory hypotheses are tested simultaneously. Without
correction, the family-wise error rate at α = 0.05 across 6 tests
would be approximately 26%. **Mitigation**: Bonferroni correction sets
the per-hypothesis threshold at 0.05 / 6 = **0.00833**. As a
robustness check, Benjamini–Hochberg FDR at q = 0.05 is also reported.
**Residual risk**: Bonferroni is conservative; it may mask genuine
effects that fail the stringent threshold. The exploratory hypotheses
(H3, H6–H11, H13) are explicitly not α-gated and are reported with
effect sizes and CIs only.

### CnV-2. Statistical power (pre-reg)

With n = 500 manifest entries (316 scannable, 298 successfully scored),
the confirmatory tests have > 95% power at the spike-observed effect
sizes (Cohen's d typically > 0.8 for H1, H2, H4). The pre-registered
effect-size thresholds (e.g., d ≥ 0.5 for H4) ensure that "supported"
verdicts correspond to practically meaningful effects, not just
statistically detectable ones. **Residual risk**: for H5 (interaction
effect in a 2 × 2 design), the effective sample size in the
ingress × delegation cell may be small (delegation prevalence = 20.1%);
power for the interaction test may be lower than for main-effect tests.

### CnV-3. Non-independence — same upstream repo across registries (pre-reg)

Multiple registries may list the same upstream GitHub repository (e.g.,
a server published to both npm and PyPI). Treating these as independent
observations would inflate effective sample size and deflate standard
errors. **Mitigation**: canonical-repo deduplication by
`(github_owner.lower(), github_repo.lower())` is applied before all
confirmatory tests, as specified in pre-reg §6. Servers without a
GitHub URL are treated as canonical entries. Duplicate counts are
reported in a descriptive table. **Residual risk**: forks and
near-duplicates with different repo names are not collapsed; these
represent a small residual source of non-independence.

### CnV-4. G3 missing data — 18 HTTPError servers, 5.7% (NEW)

Eighteen of 316 scannable servers (5.7%) errored during download with
persistent HTTPError (404 — deleted packages or moved repositories).
Per pre-reg §3, the exclusion rate threshold is 5%; at 5.7%,
sensitivity analysis is required. **Direction of bias**: if errored
servers are systematically less capable (e.g., abandoned low-quality
packages), their exclusion inflates prevalence estimates. If they are
systematically more capable (e.g., removed for security reasons), their
exclusion deflates prevalence. **Mitigation**: the confirmatory
analysis will impute each errored server twice — optimistic (ASS = 0,
no capabilities) and pessimistic (ASS = corpus max = 74.9, all
categories detected) — and re-run all 6 confirmatory tests under both
imputations. Verdict robustness is reported. **Residual risk**: any
verdict that flips between optimistic and pessimistic imputation is
flagged as fragile and reported with a caveat.

### CnV-5. LLM-as-second-rater limitation (NEW)

Per the locked decision in the project memory, the second annotator for
inter-rater reliability is Claude Sonnet 4.6, not a second human
annotator. Cohen's κ therefore measures **human-vs-LLM agreement**, not
human-vs-human agreement. **Direction of bias**: κ may be inflated if
the LLM aligns with the same heuristics as the human annotator (both
trained on similar web data, both reading the same category
definitions). Conversely, κ may be deflated if the LLM applies
different thresholds for what constitutes "detected." **Mitigation**:
(a) both raters are blind to extractor output; (b) the LLM rater works
from raw source archives only (no labeling signals, no webapp
affordances); (c) the full LLM prompt is documented in
`validation/labeling_protocol.md` for reproducibility; (d) κ is
interpreted with the caveat that it measures human–LLM agreement, not
inter-human reliability. **Residual risk**: the κ target of ≥ 0.6 may
be easier to achieve with an LLM second rater than with a human one,
since the LLM has access to the same formal category definitions. The
paper should report this limitation prominently.

### CnV-6. Operational fragility — labeling webapp dependency (NEW)

Labels are collected via a webapp deployed on the forge k3s cluster
(labeler service, Istio VirtualService routing). If the cluster or its
persistent volume claim fails, in-flight labels are at risk of loss.
**Direction**: data loss would reduce the ground-truth set size and
could bias the set toward earlier-labeled servers (which may differ
from later-labeled ones if labeling order correlates with difficulty).
**Mitigation**: explicit export-and-commit checkpoint — at every
labeling session break, labels are exported via
`curl /api/export.csv > validation/labels_arun.csv` and committed to
git. The git-committed CSV is the canonical record. **Residual risk**:
labels entered between the last checkpoint and a failure event would be
lost. The operational dependency is acknowledged; the checkpoint
frequency (every session break) limits maximum loss to one session's
work.

---

## Cross-cutting: where threats qualify specific paper sections

| Threat ID | Threat | Paper sections affected |
|-----------|--------|------------------------|
| IV-1 | H4/H5 tautology | §Results (H4, H5), §Method (operationalisation) |
| IV-2 | H2 confounding | §Results (H2), §Method (regression controls) |
| IV-3 | H4 tier confound | §Results (H4), §Method (regression controls) |
| IV-4 | Detector precision | §Results (all category-based claims), §Validation |
| IV-5 | #17 disambiguation | §Method (extractor), §Results (H2 secrets prevalence) |
| EV-1 | Sample frame | §Method (corpus), §Discussion (generalisability) |
| EV-2 | Snapshot date | §Method (corpus), §Discussion (temporal validity) |
| EV-3 | Language coverage | §Method (extractor), §Discussion (scope) |
| EV-4 | Snapshot fragility | §Method (corpus), §Discussion (replication) |
| CV-1 | ASS ≠ exploit | §Method (score function), §Discussion (interpretation) |
| CV-2 | OWASP weights | §Method (score function), §Results (sensitivity table) |
| CV-3 | Anchor ceiling | §Method (calibration), §Discussion (ASS interpretation) |
| CV-4 | Single-annotator | §Validation, §Discussion (taxonomy validity) |
| CnV-1 | Multiple comparisons | §Method (α correction), §Results (all confirmatory) |
| CnV-2 | Statistical power | §Method (power analysis), §Results (all confirmatory) |
| CnV-3 | Non-independence | §Method (deduplication), §Results (all confirmatory) |
| CnV-4 | G3 missing data | §Results (sensitivity analysis), §Discussion |
| CnV-5 | LLM second rater | §Validation (κ), §Discussion (inter-rater caveat) |
| CnV-6 | Webapp fragility | §Validation (data provenance) |
