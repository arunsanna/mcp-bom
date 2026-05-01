# Research Design: MCP-BOM

## 1. Core Research Questions (RQs)

To elevate `MCP-BOM` from a simple tool release to a scientific contribution suitable for the NeurIPS Evaluations & Datasets Track, we must ask fundamental questions about the nature of the MCP ecosystem's attack surface.

*   **RQ1 (The Capability Paradox):** Do MCP servers systematically violate the principle of least privilege by exposing high-severity capabilities (e.g., arbitrary shell execution) more frequently than low-severity capabilities (e.g., restricted filesystem reads)?
*   **RQ2 (The Proxy Blindspot):** To what extent do existing vulnerability scanners (like CWE-based static analyzers) fail to capture the true attack surface of MCP servers compared to a capability-based taxonomy?
*   **RQ3 (Ecosystem Maturity):** Is there a measurable correlation between the provenance of an MCP server (e.g., install count, maintainer reputation) and its quantitative attack-surface score?

## 2. Testable Hypotheses

Based on the RQs, we formulate the following hypotheses to test against our 500-server corpus.

### Hypothesis 1: The "Execution-First" Asymmetry
**H1:** *In the MCP ecosystem, the prevalence of "Shell / Process Execution" capabilities will significantly exceed the prevalence of "Filesystem" capabilities.*

*   **Rationale:** Traditional software typically requires broad filesystem access but rarely exposes arbitrary shell execution. We hypothesize the inverse is true for MCP servers, as they are explicitly designed to grant LLMs "agency" (the ability to act), leading developers to over-provision execution rights while neglecting granular filesystem controls.
*   **Expected Observation:** The static extractor will find a higher percentage of servers with the `shell` capability than the `filesystem` capability.

### Hypothesis 2: The CWE Measurement Gap
**H2:** *Servers scoring low on traditional CWE-based risk assessments (e.g., those with zero detected coding flaws) can still score in the top quartile (≥ 75) of the MCP-BOM attack-surface metric.*

*   **Rationale:** Competitors like `MCP-in-SoS` measure accidental coding flaws (CWEs). However, a perfectly written Python script that intentionally exposes `subprocess.run(shell=True)` to an LLM is highly dangerous but contains no "bug." We hypothesize that measuring intended capabilities captures a critical risk dimension that CWEs miss.
*   **Expected Observation:** A subset of servers in our corpus will have high MCP-BOM scores but would theoretically pass standard SAST tools without critical alerts.

### Hypothesis 3: The Popularity Penalty
**H3:** *The top 10% most downloaded MCP servers will exhibit a higher average attack-surface score than the long-tail (bottom 50%) servers.*

*   **Rationale:** Highly downloaded servers (often provided by major platforms or designed as "universal" tools) tend to be "kitchen sink" implementations that bundle numerous capabilities to maximize utility, inherently violating least privilege. Long-tail servers are often built for narrow, specific tasks.
*   **Expected Observation:** A positive correlation between `install_count` and the final `ASS` (Attack-Surface Score).

## 3. Experimental Methodology

To test these hypotheses, we will execute the following experimental pipeline during our 6-day sprint:

### Experiment 1: Capability Distribution Analysis (Tests H1)
1.  Run the `mcp_bom` static extractor across the 500-server corpus.
2.  Calculate the frequency distribution of the 9 capability categories.
3.  **Analysis:** Compare the raw count and percentage of servers exposing Category 2 (Shell) vs. Category 1 (Filesystem). 

### Experiment 2: The "Intended vs. Accidental" Comparison (Tests H2)
1.  Identify the top 20 highest-scoring servers according to the MCP-BOM score function.
2.  Manually review the source code of these 20 servers to determine if the high score is driven by *intended design* (e.g., a "terminal" tool) or *accidental flaws* (e.g., command injection via poor string formatting).
3.  **Analysis:** Quantify the percentage of high-risk capabilities that are explicitly declared in the `tools/list` schema versus those hidden in the implementation.

### Experiment 3: Provenance Correlation (Tests H3)
1.  Using the `corpus/scored_500.json` output, plot the Attack-Surface Score (y-axis) against the log of the install count (x-axis).
2.  Calculate the Pearson correlation coefficient between the two variables.
3.  **Analysis:** Determine if popularity drives over-provisioning.

## 4. Expected Impact for NeurIPS

By framing the paper around these hypotheses, we transition from "Here is a tool that scores servers" to "Here is a scientific evaluation of how the AI agent ecosystem fundamentally misunderstands least privilege." This directly aligns with the NeurIPS 2026 E&D Track's mandate to treat evaluation as a scientific object of study.
