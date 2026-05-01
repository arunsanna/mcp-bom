# End-to-End Strategy: MCP-BOM for NeurIPS 2026

**Target Venue:** NeurIPS 2026 Evaluations & Datasets (E&D) Track  
**Submission Deadline:** May 6, 2026 (AoE)  
**Author:** Arun Chowdary Sanna

---

## 1. Executive Summary

This document outlines a comprehensive, end-to-end strategy to maximize the acceptance probability of the `mcp-bom` paper at the NeurIPS 2026 Evaluations & Datasets (E&D) Track. The strategy bridges the gap between the current repository scaffolding and a top-tier conference submission, incorporating the latest 2026 E&D Track guidelines, a critical update to the competitive landscape, and actionable implementation tactics for the tight 6-day timeline.

## 2. Competitive Landscape & Novelty Positioning

A successful NeurIPS submission requires precise differentiation from prior art. Recent research has uncovered a critical competitor not currently listed in the `mcp-bom` prior art assessment.

### 2.1 The New Threat: `MCP-in-SoS`
A recent paper, "MCP-in-SoS: Risk assessment framework for open-source MCP servers" (Kumar et al., March 2026) [1], introduces a risk-assessment framework for MCP servers using static code analysis. 

**How to Differentiate `MCP-BOM`:**
The `mcp-bom` paper must explicitly contrast itself with `MCP-in-SoS` in the Related Work section. The differentiation strategy should emphasize:
1.  **Taxonomy Origin:** `MCP-in-SoS` relies on generic software weaknesses (CWE) mapped to CAPEC. `MCP-BOM` introduces an **MCP-specific, 8-category permission taxonomy** tailored to agentic workflows.
2.  **Scoring Foundation:** `MCP-BOM`'s scoring is explicitly derived from the **OWASP Agentic Top 10** severity weights, providing a domain-specific risk assessment rather than a generic likelihood/impact matrix.
3.  **The Benchmark Artifact:** `MCP-BOM` is not just a methodology; it delivers a reproducible, labeled benchmark corpus of 500 servers, fulfilling the core mandate of the NeurIPS E&D track.

### 2.2 Positioning for the E&D Track
The 2026 E&D Track explicitly broadened its scope to treat "evaluation as a scientific object of study" [2]. The paper must be framed not just as a tool release, but as a methodological advance in how we evaluate the attack surface of agentic components. 

**Key Framing Statement for Introduction:** 
> "We propose MCP-BOM, a novel evaluation methodology and accompanying benchmark dataset that shifts the assessment of MCP servers from binary vulnerability scanning to a quantitative, capability-based attack-surface score."

## 3. Implementation Strategy (The 6-Day Sprint)

Given the May 6 AoE deadline, execution must be flawless.

### 3.1 Day 1-2: Extractor Development & The AST Challenge
Building a multi-language AST parser in one day is the highest project risk.
*   **Tactic:** Limit the v1 extractor to **Python only**. Python is the dominant language for MCP servers. Attempting TypeScript and Go concurrently will likely derail the timeline.
*   **Fallback:** If the Python AST parser is incomplete by Day 2 evening, immediately pivot to the documented fallback: **manual labeling of the top 200 servers**. A high-quality, manually verified dataset of 200 servers is sufficient for a NeurIPS submission; a broken automated tool is not.

### 3.2 Day 3: Corpus Construction & Hosting
The NeurIPS 2026 guidelines mandate strict data hosting requirements [3].
*   **Platform:** Host the 500-server benchmark (or 200 if using the fallback) on **Hugging Face**. It supports the required gated access (useful for responsible disclosure of high-risk servers) and automatically generates the core Croissant metadata fields [4].
*   **Anonymization:** The E&D track defaults to double-blind review [3]. The Hugging Face dataset must be published under an anonymous account.

### 3.3 Day 4: Validation Suite
Reviewers will heavily scrutinize the validation of the score function.
*   **Inter-rater Reliability:** This is crucial. Calculate Cohen's Kappa on a 50-server subset to prove the taxonomy is objective.
*   **CVE Correlation:** Demonstrate that known severe vulnerabilities (e.g., CVE-2025-6514) score ≥ 80. This anchors the score function to ground truth.

## 4. Paper Writing & Submission Tactics

### 4.1 Structure and Narrative Flow
*   **Abstract & Intro:** Clearly state the problem (MCP lacks least privilege), the gap (no per-server numeric scoring or reproducible benchmark), and the contribution (taxonomy, score function, 500-server corpus).
*   **Methodology:** Detail the 8-category taxonomy and the deterministic 0-100 score function. Be transparent about the confidence multipliers.
*   **Results (The Benchmark):** Present the score distribution of the 500 servers. Use histograms and heatmaps. Highlight surprising findings (e.g., highly downloaded servers with excessive permissions).
*   **Validation:** Present the Cohen's Kappa scores and CVE correlation results.
*   **Limitations:** Be brutally honest. NeurIPS rewards transparency. Acknowledge if the extractor only supports Python in v1, or if dynamic analysis is deferred to future work.

### 4.2 Mandatory Submission Artifacts
To avoid desk rejection, the following must be ready by May 6 AoE:
1.  **The Paper (PDF):** Formatted using the NeurIPS 2026 LaTeX template, fully anonymized.
2.  **The Code:** The extractor source code, hosted on an anonymized GitHub repository. **Code release at submission is mandatory** for executable artifacts like `mcp-bom` [3].
3.  **The Dataset:** Hosted on Hugging Face (anonymous).
4.  **Croissant Metadata:** The `croissant.json` file, including both core fields (auto-generated by Hugging Face) and **Responsible AI (RAI) fields** (manually added via the NeurIPS online tool) [4].
5.  **NeurIPS Paper Checklist:** Must be included in the paper PDF after the references [5].

## 5. Summary of Action Items

1.  **Update Prior Art:** Add `MCP-in-SoS` to `docs/prior-art-assessment.md` and define the differentiation strategy.
2.  **Scope Reduction:** Restrict the Day 2 extractor build to Python only to ensure completion.
3.  **Prepare Anonymous Infrastructure:** Create anonymous GitHub and Hugging Face accounts immediately.
4.  **Draft the Paper Checklist:** Review the NeurIPS paper checklist early to ensure the methodology covers all required points (especially regarding limitations and reproducibility).

---

## References

[1] P. Kumar et al., "MCP-in-SoS: Risk assessment framework for open-source MCP servers," *arXiv preprint arXiv:2603.10194*, 2026. Available: https://arxiv.org/abs/2603.10194

[2] NeurIPS Blog, "Introducing the Evaluations & Datasets Track at NeurIPS 2026," Mar. 2026. Available: https://blog.neurips.cc/2026/03/23/introducing-the-evaluations-datasets-track-at-neurips-2026/

[3] NeurIPS, "Call For Evaluations & Datasets 2026." Available: https://neurips.cc/Conferences/2026/CallForEvaluationsDatasets

[4] NeurIPS, "Evaluations & Datasets Hosting 2026." Available: https://neurips.cc/Conferences/2026/EvaluationsDatasetsHosting

[5] NeurIPS, "Paper Checklist Guidelines." Available: https://neurips.cc/public/guides/PaperChecklist
