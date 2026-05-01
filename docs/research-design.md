# Research Design: MCP-BOM

## 1. Core Research Questions (RQs)

To elevate `MCP-BOM` from a simple tool release to a scientific contribution suitable for the NeurIPS Evaluations & Datasets Track, we must ask fundamental questions about the nature of the MCP ecosystem's attack surface.

*   **RQ1 (The Capability Sprawl):** Do MCP servers inherently violate the principle of least privilege by bundling multiple orthogonal capabilities (e.g., filesystem + network + secrets) rather than adhering to single-responsibility design?
*   **RQ2 (The Secrets Gateway):** Does the presence of secrets-management capabilities (e.g., environment variable access) act as a reliable predictor for a dramatically expanded attack surface across other categories?
*   **RQ3 (The Language Divide):** Is there a structural difference in attack-surface risk between the TypeScript/Node.js ecosystem (npm) and the Python ecosystem (PyPI) for MCP servers?
*   **RQ4 (The CWE Blindspot):** To what extent do traditional vulnerability scanners (which measure coding flaws) fail to capture the intended capability risk of MCP servers compared to a taxonomy-based attack-surface score?

## 2. Testable Hypotheses

Based on the RQs and initial spike data, we formulate the following hypotheses to test against our 500-server corpus.

### Hypothesis 1: The "Multi-Capability Default" (Sprawl)
**H1:** *The average MCP server exposes capabilities across 3 or more distinct categories, rather than adhering to a single-responsibility design.*

*   **Rationale:** Unlike traditional microservices that restrict scope, MCP servers are designed to give LLMs broad agency. Developers tend to build "kitchen sink" servers (e.g., a single server that reads files, makes network requests, and executes shell commands) to maximize the utility of the LLM connection, fundamentally violating least privilege.
*   **Expected Observation:** The mean number of detected capability categories per server will be ≥ 3.0.

### Hypothesis 2: The Secrets-Gateway Effect
**H2:** *Servers that require access to secrets (e.g., API keys, environment variables) will exhibit an attack-surface score at least 2x higher than servers without secrets access.*

*   **Rationale:** Secrets are rarely used in isolation. A server that reads an API key almost certainly uses it to make network requests (egress), and likely saves data to the filesystem or a database. Secrets act as a "gateway" capability that necessitates other high-risk capabilities.
*   **Expected Observation:** The average Attack-Surface Score (ASS) of servers with the `secrets` capability will be significantly higher (≥ 2x) than those without.

### Hypothesis 3: The TypeScript/Python Divide
**H3:** *TypeScript MCP servers (primarily from npm) will exhibit a broader capability spread and higher average attack-surface score than Python servers (primarily from PyPI).*

*   **Rationale:** The Node.js/npm ecosystem has historically favored highly composable, broad-access patterns compared to Python's ecosystem. Additionally, enterprise platforms (which require complex integrations) often default to TypeScript for their official MCP SDKs.
*   **Expected Observation:** A statistically significant difference in mean ASS between the two languages.

### Hypothesis 4: The Ingress Risk Multiplier
**H4:** *The presence of network ingress (listening on a port) acts as a primary driver for top-quartile attack-surface scores, strongly co-occurring with filesystem and secrets access.*

*   **Rationale:** An MCP server that listens for inbound connections (e.g., via SSE or custom HTTP endpoints) fundamentally shifts the threat model from local-only execution to remote exploitability.
*   **Expected Observation:** Servers with the `ingress` capability will dominate the top 10% of the highest-scoring servers in the corpus.

## 3. Experimental Methodology

To test these hypotheses, we will execute the following experimental pipeline during our 6-day sprint:

### Experiment 1: Capability Sprawl Analysis (Tests H1 & H4)
1.  Run the `mcp_bom` static extractor across the 500-server corpus.
2.  Calculate the mean and median number of detected categories per server.
3.  Generate a conditional co-occurrence matrix (Heatmap) to identify which capabilities (like `ingress` and `filesystem`) frequently bundle together.

### Experiment 2: The Gateway Analysis (Tests H2)
1.  Partition the scored corpus into two sets: `secrets_detected == True` and `secrets_detected == False`.
2.  Perform a Welch's t-test to compare the mean Attack-Surface Scores of both groups.
3.  Analyze the average number of distinct capabilities in the `secrets` group versus the non-secrets group.

### Experiment 3: Ecosystem Comparison (Tests H3)
1.  Partition the corpus by primary language (`python` vs `typescript`).
2.  Compare the mean ASS, depth scores, and breadth scores between the two ecosystems.
3.  Identify if certain capabilities (e.g., `shell` or `impersonation`) are disproportionately favored by one language.

## 4. Expected Impact for NeurIPS

By framing the paper around these hypotheses, we transition from "Here is a tool that scores servers" to "Here is a scientific evaluation of how the AI agent ecosystem fundamentally misunderstands least privilege." This directly aligns with the NeurIPS 2026 E&D Track's mandate to treat evaluation as a scientific object of study.
