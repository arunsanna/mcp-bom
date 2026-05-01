# MCP-BOM Six-Day Build Plan

> May 1 → May 6, 2026. NeurIPS ED hard freeze: May 6 AoE.

## Day 1 — Friday May 1

**Goal**: corpus + taxonomy + score function frozen.

- [ ] Scrape 500 MCP servers from npm `@modelcontextprotocol`, npm keyword `mcp-server`, PyPI matching keywords, GitHub topic `mcp-server`, mcp.run catalogue. Stratify by install count.
- [ ] Output `corpus/manifest.json` with package name, version, downloads, repo URL, source archive path.
- [ ] Create anonymous Hugging Face account and GitHub repository for double-blind submission.
- [x] Resolve open questions in `docs/capability-taxonomy.md` (unsafe deserialization classification, generic HTTP, DB access).
- [x] Lock `docs/score-function.md` weights and depth tables; check in `score_function.toml`.
- [ ] Repo is now ready for extractor build.

## Day 2 — Saturday May 2

**Goal**: working extractor on first 100 servers.

- [ ] Implement `extractor/mcp_bom/extractor.py` — capability scope detection across the eight categories (focus on **Python ONLY** for v1 to ensure completion).
- [ ] Implement `extractor/mcp_bom/scorer.py` — score function from spec.
- [ ] Run on first 100 Python servers from corpus. Inspect outputs by hand.
- [ ] Iterate on detection rules where false positives or false negatives appear.
- [ ] Lock extractor v1 by end of day.

## Day 3 — Sunday May 3

**Goal**: full corpus scored + score distribution figure.

- [ ] Run extractor on full 500-server corpus.
- [ ] Compute attack-surface score per server.
- [ ] Generate score distribution histogram + by-category breakdown.
- [ ] Identify top 20 highest-score servers; spot-check by hand for plausibility.
- [ ] Output `corpus/scored_500.json` with per-server score and capability vector.
- [ ] Upload dataset to anonymous Hugging Face repo.
- [ ] Generate `croissant.json` metadata file including Core fields (auto-generated) and Responsible AI (RAI) fields (manual via NeurIPS tool).

## Day 4 — Monday May 4

**Goal**: validation done + abstract submitted.

- [ ] Inter-rater reliability: two human reviewers (self + one other) label held-out 50-server subset; compute Cohen's κ.
- [ ] MCPLIB attack replay: take 31 attack types from arXiv:2508.12538; test against scored servers; report attack success rate by score bucket.
- [ ] CVE correlation: confirm CVE-2025-6514, CVE-2025-49596 land at top of distribution.
- [ ] Cross-source consistency: identify same-server-different-registry pairs; report score variance.
- [ ] Complete NeurIPS Paper Checklist (focusing on reproducibility and limitations).
- [ ] Submit NeurIPS ED abstract by May 4 AoE.

## Day 5 — Tuesday May 5

**Goal**: paper draft + repo freeze.

- [ ] Paper sections: introduction, related work, methodology, results, discussion, limitations, conclusion.
- [ ] Tables: prior-art gap (from `docs/prior-art-assessment.md` including explicit differentiation from `MCP-in-SoS`), category descriptors, weight table, top-20 highest-score servers, validation results.
- [ ] Figures: score distribution histogram, by-category exposure heatmap, ROC curve for MCPLIB attack vs score.
- [ ] Self-review against NeurIPS ED reviewer questionnaire.
- [ ] Tag repo `v1.0-neurips-ed-2026`. Push.

## Day 6 — Wednesday May 6

**Goal**: paper polish + final submission AoE.

- [ ] Final paper polish: pacing, abstract rewrite, citation pass.
- [ ] Submit full paper + supplementary materials by May 6 AoE.
- [ ] Capture submission evidence: confirmation email, OpenReview submission ID, screenshot of submitted version, repo tag URL.
- [ ] Ensure code is uploaded to anonymous GitHub repo (mandatory for ED Track at submission time).
- [ ] Backup all artifacts to `evidence/` for EB1A record.

## Daily Check-ins

End of each day:

- Update progress in `EB1A-040`, `EB1A-041`, and the day's specific build task in AI Memory.
- Log blockers; don't push past midnight without escalation.
- Quick scan: has Cisco published their scoring methodology yet? Has a new arXiv preprint dropped?

## Escalation Triggers

- Day 2 end: extractor not producing usable output → fall back to manual labeling for top 200 (still a NeurIPS-shaped contribution).
- Day 4 end: validation contradicts score function design → ship as v1, document discrepancy in limitations, fix in camera-ready.
- Day 5: paper writing taking longer than estimated → cut discussion section, keep results tight.
