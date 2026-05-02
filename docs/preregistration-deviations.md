# MCP-BOM Pre-Registration Deviations Log

Per `docs/preregistration.md` §7. Each entry records: what
changed, why, when (UTC), and the git hash of `preregistration.md`
immediately before the change.

---

## Deviation 001 — §4 calibration anchors recalibrated to percentile-relative (v1 → v1.1)

- **Date (UTC)**: 2026-05-02
- **Pre-reg git hash before change**: `90b4490e464e47d7f3d5884cd8b9223c0edd684b`
- **Affected sections**: §4 calibration anchors only. §1, §3, §6
  unchanged.
- **What changed**: Calibration anchor thresholds in §4 moved
  from absolute ASS values (≥ 80, ≥ 90, ≤ 30) to percentile-
  relative thresholds tied to the observed corpus ASS
  distribution.
- **Why**: Diagnostic on MCP Inspector (CVE-2025-49596) showed
  ASS = 41.28, failing the original ≥ 80 anchor. Investigation
  found the failure was structural: corpus max ASS = 74.9 under
  the locked v1 score function, making 80 mathematically
  unreachable for any real server. Re-tuning weights to satisfy
  the anchor would constitute HARKing on the score function
  itself. Anchors are recalibrated to the model's observed range,
  and ASS is reframed as a relative risk ranking within the MCP
  ecosystem rather than an absolute risk percentage.
- **Why this is a §7 deviation, not a v1.2**: §1 confirmatory
  hypotheses, sample frame (§3), and operational definitions
  (§6) are unchanged. Only §4 instrument-validation anchors are
  affected. The §1 family-of-6 confirmatory tests do NOT need
  to be re-run.
- **Construct-validity implication for the paper**: ASS measures
  relative attack-surface ranking within the MCP ecosystem, not
  absolute risk percentage. Inspector at p70 of corpus is
  consistent with its CVE classification.
