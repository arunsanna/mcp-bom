# Extended Research Hypotheses for MCP-BOM

Drawing on attack-surface measurement theory (Manadhata & Wing, 2011) [1], software supply chain economics, and recent findings on agentic AI security (e.g., OWASP Agentic Top 10 [2], UpGuard lookalike analysis [3]), we formulate 10 additional world-class research hypotheses. These hypotheses elevate the `MCP-BOM` paper from a simple measurement tool to a fundamental critique of the emerging AI agent ecosystem.

---

## Part 1: Structural Attack Surface & The Manadhata-Wing Model

Manadhata and Wing (2011) formalized attack surface as the sum of a system's entry points, exit points, channels, and untrusted data items [1]. In the MCP ecosystem, the "system" boundary is inverted: the server is the execution environment, and the LLM is the untrusted input channel.

### H5: The "Inverted Boundary" Asymmetry
**Hypothesis:** *MCP servers that expose both `ingress` (network listening) and `delegation` (calling other MCP servers) will exhibit a super-linear increase in their Attack-Surface Score compared to servers with only one of these capabilities.*
*   **Rationale:** In traditional systems, ingress is an entry point. In MCP, delegation creates a dynamic, recursive exit point where an LLM can chain capabilities across servers. When combined, they create an unbounded execution graph that shatters traditional perimeter defense.
*   **Test:** Compare the mean ASS of the (ingress ∩ delegation) set against the sum of the independent means of the `ingress`-only and `delegation`-only sets.

### H6: The Co-Location Paradox
**Hypothesis:** *Capabilities that manage sensitive state (e.g., `secrets`, `database`) will co-occur with arbitrary execution capabilities (e.g., `shell`) at a rate significantly higher than random chance would predict.*
*   **Rationale:** Traditional security engineering isolates state management from arbitrary execution. We hypothesize that MCP developers, optimizing for LLM "utility," routinely violate this isolation, co-locating the keys to the kingdom with the means to exfiltrate them.
*   **Test:** Calculate the Pointwise Mutual Information (PMI) between `secrets`/`database` and `shell` across the corpus.

---

## Part 2: Supply Chain Economics & Provenance

The MCP ecosystem is heavily reliant on open-source package managers (npm, PyPI) which suffer from well-documented supply chain vulnerabilities like typosquatting [3].

### H7: The "Lookalike" Risk Premium
**Hypothesis:** *MCP servers identified as "lookalikes" or typosquats (e.g., `mcp-postgress` vs. `@modelcontextprotocol/server-postgres`) will exhibit significantly higher attack-surface scores than the canonical packages they imitate.*
*   **Rationale:** Adversaries creating lookalike packages [3] are economically incentivized to maximize the utility of a successful compromise by over-provisioning capabilities (e.g., adding `shell` or `egress` to a fake database server) to facilitate data exfiltration or lateral movement.
*   **Test:** Identify a subset of lookalike packages in the corpus using Levenshtein distance on package names. Compare their mean ASS to their canonical counterparts.

### H8: The Registry Governance Gap
**Hypothesis:** *MCP servers sourced from unmoderated registries (e.g., GitHub-only or community lists like mcp.so) will have a higher variance in Attack-Surface Scores than servers sourced from official orgs on npm/PyPI.*
*   **Rationale:** Without centralized security governance or standardized review processes, community registries become the "wild west" of capability exposure. We expect to see both highly restricted, single-purpose tools and massive, over-provisioned "kitchen sink" tools.
*   **Test:** Compare the standard deviation of ASS for GitHub-only servers versus official npm/PyPI servers.

### H9: The "Stale Server" Decay
**Hypothesis:** *MCP servers that have not been updated in >90 days will exhibit a higher prevalence of high-risk capabilities (like `shell`) compared to actively maintained servers.*
*   **Rationale:** The MCP protocol and its security best practices are evolving rapidly. Early servers (built in late 2024/early 2025) were likely built as rapid prototypes with broad permissions. Actively maintained servers are more likely to have been refactored to adhere to emerging least-privilege norms.
*   **Test:** Correlate the `last_update` timestamp from the corpus manifest with the presence of Category 2 (Shell) capabilities.

---

## Part 3: Sociotechnical Dynamics of AI Agents

How developers build tools for AI agents differs fundamentally from how they build tools for humans.

### H10: The "Human-in-the-Loop" Illusion
**Hypothesis:** *Servers exposing `impersonation` capabilities (e.g., sending emails, posting to Slack) will almost never implement explicit approval gates (e.g., requiring a user click before sending) within the server code itself.*
*   **Rationale:** Developers assume the LLM client (e.g., Claude Desktop) will handle user confirmation. However, if the server is used headlessly or by an autonomous agent, this creates a massive confused-deputy risk. The server delegates safety to a client it cannot verify.
*   **Test:** Analyze the AST of servers with `impersonation` capabilities for the presence of interactive prompt patterns (e.g., `input()`, `inquirer`).

### H11: The "God Mode" Default
**Hypothesis:** *Database-capable MCP servers will default to establishing connections with administrative/root privileges rather than enforcing read-only or scoped user roles.*
*   **Rationale:** To maximize the LLM's ability to "help" the user (e.g., creating tables, altering schemas), developers will hardcode or default to high-privileged connection strings, ignoring the principle of least privilege at the data layer.
*   **Test:** Analyze the connection string parsing logic in servers with the `database` capability for default user roles or the absence of read-only enforcement.

---

## Part 4: The CWE Blindspot (Deepening H4)

Expanding on our earlier finding that traditional SAST tools miss MCP-specific risks.

### H12: The Orthogonality of CWE and Capability Risk
**Hypothesis:** *There is no statistically significant correlation between the number of traditional coding flaws (CWEs) in an MCP server and its MCP-BOM Attack-Surface Score.*
*   **Rationale:** As demonstrated by the `MCP-in-SoS` paper [4], CWE scanners find accidental bugs. `MCP-BOM` measures intended capabilities. A highly capable, perfectly written server (High ASS, Low CWE) is fundamentally different from a narrowly scoped, buggy server (Low ASS, High CWE). They measure orthogonal risk dimensions.
*   **Test:** Run a standard SAST tool (e.g., Semgrep) over a 50-server subset. Calculate the correlation between the SAST finding count and the MCP-BOM ASS.

### H13: The "Safe Language" Fallacy
**Hypothesis:** *Memory-safe languages (like Go or Rust, if present in the corpus) will not exhibit lower Attack-Surface Scores than Python or TypeScript.*
*   **Rationale:** Memory safety eliminates buffer overflows (CWE-119), but it does not prevent a developer from writing a tool that intentionally executes arbitrary shell commands. In the agentic paradigm, memory safety provides zero defense against capability over-provisioning.
*   **Test:** Compare the mean ASS of servers written in Go/Rust versus Python/TypeScript.

### H14: The Schema vs. Implementation Drift
**Hypothesis:** *Over 20% of MCP servers will contain "hidden" capabilities in their source code that are not explicitly declared in their `tools/list` JSON schema.*
*   **Rationale:** Developers may import dangerous libraries (e.g., `os`, `subprocess`) for utility functions but fail to document these capabilities in the LLM-facing schema. This creates a "shadow attack surface" where an attacker who compromises the server via prompt injection can access capabilities the LLM itself doesn't know exist.
*   **Test:** Compare the capabilities detected in the AST pass against the capabilities detected purely from the `tools/list` schema definitions.

---

## References

[1] P. K. Manadhata and J. M. Wing, "An Attack Surface Metric," *IEEE Transactions on Software Engineering*, vol. 37, no. 3, pp. 371-386, 2011.

[2] OWASP, "OWASP Top 10 for Agentic Applications 2026." Available: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

[3] UpGuard, "1 in 15 MCP Servers are Lookalikes: Is Your Org at Risk?" April 2026. Available: https://www.upguard.com/blog/mcp-server-lookalikes

[4] P. Kumar et al., "MCP-in-SoS: Risk assessment framework for open-source MCP servers," *arXiv preprint arXiv:2603.10194*, 2026. Available: https://arxiv.org/abs/2603.10194
