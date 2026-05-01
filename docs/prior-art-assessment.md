# Prior-Art Assessment — MCP Permission and Attack-Surface Tooling

> Compiled April 30, 2026. Source: research-explorer agent scan plus live verification of arXiv:2506.13538 v5. Used to confirm the novelty gate for MCP-BOM submission to NeurIPS 2026 ED.

## Section 1 — Closest Existing Work

### Snyk Agent Scan (formerly MCP-Scan, Invariant Labs)

- Org: Invariant Labs (ETH Zurich spin-off), acquired by Snyk June 2025. v0.4.13, April 2026.
- What it does: static scan of installed MCP server tool descriptions. Detects prompt injection, tool poisoning (hidden instructions in descriptions), rug pulls (description hash changes), cross-origin escalation. Runtime proxy mode for live traffic monitoring.
- Scoring: no aggregate numeric attack-surface score. Categorical findings list only.
- Permission inventory: pattern-only, not systematic capability-scope mapping.
- Source: https://invariantlabs.ai/blog/introducing-mcp-scan | https://github.com/invariantlabs-ai/mcp-scan

### Cisco AI Defense MCP Scanner

- Org: Cisco. Open-source Python tool, 2025.
- What it does: scans MCP tool definitions using YARA rules, LLM-as-judge, and Cisco AI Defense backend. Detects semantic and behavioral anomalies in tool code and descriptions.
- Scoring: enterprise tier mentions "dynamic risk scoring" but methodology is proprietary and unpublished. Open-source tier: categorical findings.
- Permission inventory: no structured taxonomy.
- Source: https://blogs.cisco.com/ai/securing-the-ai-agent-supply-chain-with-ciscos-open-source-mcp-scanner | https://cisco-ai-defense.github.io/docs/mcp-scanner

### Proximity (Nova-Proximity, fr0gger)

- Org: community open-source. Released October 2025.
- What it does: inventories prompts, tools, and resources a server exposes; runs NOVA rule engine for prompt injection and jailbreak patterns. Outputs JSON/Markdown.
- Scoring: flagged counts per category but no aggregate numeric score. Not a reproducible benchmark.
- Source: https://www.helpnetsecurity.com/2025/10/29/proximity-open-source-mcp-security-scanner/ | https://github.com/fr0gger/proximity

### Hasan et al. — arXiv:2506.13538 (v5, April 13, 2026)

- Authors: Mohammed Mehedi Hasan, Hao Li, Emad Fallahzadeh, Gopi Krishnan Rajbahadur, Bram Adams, Ahmed E. Hassan
- What it does: first large-scale empirical study of 1,899 open-source MCP servers — static analysis for code smells, bug patterns, security issues using a general-purpose static analysis tool combined with MCP-Scan. Reports aggregate stats (66% have code smells; 14.4% bug patterns; 7.2% general vulnerabilities; 5.5% MCP-specific tool poisoning).
- Per-server scoring: NO. Population-level statistics only. Verified live April 30, 2026 — v5 retains aggregate-only reporting.
- Permission taxonomy: NO.
- Why it matters: closest academic analog. Establishes corpus approach but stops at aggregate health metrics.
- Source: https://arxiv.org/abs/2506.13538

### MCP-in-SoS — arXiv:2603.10194 (March 2026)

- Authors: Pratyay Kumar, Miguel Antonio Guirao Aguilera, Srikathyayani Srikanteswara, Satyajayant Misra, Abu Saleh Md Tayeen
- What it does: Risk-assessment framework for open-source MCP servers. Uses static code analysis (CodeQL, Joern, Cisco Scanner) to identify CWEs and maps them to CAPEC attack patterns.
- Scoring: Computes a "Risk Index" per weakness and a repository-level risk score.
- Permission taxonomy: NO. It uses generic software weaknesses (CWEs) rather than an MCP-specific capability/permission taxonomy.
- Corpus: 222 Python-only servers from GitHub.
- Why it matters: The most direct competitor. It performs per-server scoring. However, its scoring relies on MITRE metadata that the authors admit is heavily missing (76% of CWE exploit likelihood data is missing), and it measures coding flaws rather than intended capability attack surfaces.
- Source: https://arxiv.org/abs/2603.10194

### MCP-SEC — IEEE S&P 2026 (arXiv:2509.06572 v4, April 2026)

- Authors: Zhao et al. (NSSL-SJTU)
- What it does: Large-scale analysis of "Parasitic Toolchain Attacks" on the MCP ecosystem. Analyzed 12,230 tools across 1,360 servers.
- Scoring: NO per-server numeric attack-surface score. Focuses on attack taxonomy and finding exploitable gadgets.
- Permission taxonomy: NO.
- Source: https://arxiv.org/abs/2509.06572

### MCPLIB — arXiv:2508.12538 (2025)

- What it does: catalogs 31 MCP attack types in four categories. Simulation framework.
- Scoring: NO real-world corpus. Attack taxonomy paper only.
- Source: https://arxiv.org/pdf/2508.12538

### OWASP AIBOM Generator

- Authors: Helen Oakley, Dmitry Raidman (contributed to OWASP Dec 2025)
- What it does: generates CycloneDX 1.6 AI-BOM for Hugging Face models. Calculates completeness score.
- Scoring: completeness only, not security risk. No MCP coverage.
- Source: https://genai.owasp.org/resource/owasp-aibom-generator/

### Summary Gap Table

| Tool / Work                        | Permission Inventory | Per-Server Score                     | Real-World Corpus | Peer-Reviewed |
| ---------------------------------- | -------------------- | ------------------------------------ | ----------------- | ------------- |
| Snyk Agent Scan (Invariant)        | Pattern-only         | No                                   | No                | No            |
| Cisco MCP Scanner                  | No                   | Enterprise-only, methodology private | No                | No            |
| Proximity                          | Categorical flags    | No                                   | No                | No            |
| Hasan et al. (arXiv:2506.13538 v5) | No                   | No (aggregate stats only)            | 1,899 servers     | arXiv only    |
| MCP-in-SoS (arXiv:2603.10194)      | No (uses generic CWE)| Yes (but theoretical/imputed data)   | 222 Python-only   | arXiv only    |
| MCP-SEC (arXiv:2509.06572)         | No                   | No                                   | 1,360 servers     | IEEE S&P 2026 |
| MCPLIB (arXiv:2508.12538)          | No                   | No                                   | Simulation only   | arXiv only    |
| OWASP AIBOM Generator              | No                   | Completeness only                    | HF models only    | No            |

No existing tool or paper combines all three: structured permission inventory + numeric per-server attack-surface score + reproducible corpus across real-world MCP servers.

## Section 2 — Adjacent Work to Cite

### MCP Security Incidents and Studies

- CVE-2025-6514 (CVSS 9.6): `mcp-remote` RCE via untrusted server connection.
- CVE-2025-49596 (CVSS 9.4): MCP Inspector CSRF → RCE chain.
- arXiv:2503.23278 (Hou et al.): MCP lifecycle + threat taxonomy. Foundational threat model.
- arXiv:2511.20920: MCP risks, controls, and governance. Proposes SBOM-style vetting pipeline.
- Trend Micro survey: 492 publicly exposed MCP servers with no auth.
- Backslash Security NeighborJack: MCP servers bound to `0.0.0.0`, exploitable by LAN neighbors.
- arXiv:2601.17548: SoK on prompt injection in agentic coding assistants; 78-study meta-analysis.
- OWASP MCP Top 10: active project, qualitative framework. https://owasp.org/www-project-mcp-top-10/

### AI-BOM and Agent Transparency Tooling

- OWASP AIBOM Generator (Oakley & Raidman, RSAC 2025).
- Agent Security Bench (ICLR 2025): 27 attack/defense types; Net Resilient Performance (NRP) metric — closest existing quantitative agent security score.
- arXiv:2510.11108: access control vision for LLM agent systems — argues for continuous dataflow-aware permission model over static allow/deny.
- CycloneDX #702 (opened Oct 2025, Matt Rutkowski): names "agent cards" as a concept; no field schema as of April 2026. Milestone Aug 2026.

### Conventional Security Theory to Adapt

- Manadhata & Wing (IEEE TSE 2011): foundational attack-surface measurement framework — entry points × accessibility × damage potential. Cleanest theoretical anchor.
- CVSS v4.0: per-component severity primitive, adaptable as per-capability scoring.
- OWASP Risk Rating Methodology: likelihood × impact grid.
- Cosseter (IEEE S&P 2026): demand-driven static analysis for GitHub Actions permission reduction — direct structural analog from a different domain.

## Section 3 — The Genuine Gap

Three capabilities have not been combined anywhere:

1. **Structured permission inventory.** No existing scanner maps MCP tool capabilities to a taxonomy of capability scopes — filesystem read/write, shell execution, network egress/ingress, secret access, inter-server delegation, human impersonation, data sensitivity. Snyk Agent Scan detects malicious patterns; it does not enumerate what a benign-but-overprivileged server can actually do. The distinction matters: a tool with zero detectable poisoning can still expose arbitrary shell execution to any caller.

2. **Numeric attack-surface score per server based on capabilities.** While `MCP-in-SoS` (arXiv:2603.10194) recently introduced a risk score, it measures generic coding flaws (CWEs) and relies on sparse MITRE metadata. An MCP server can be perfectly coded (zero CWEs) but still expose highly dangerous capabilities (e.g., arbitrary shell execution) to an LLM. MCP-BOM scores the *intended attack surface* using OWASP Agentic Top 10 weights, not just accidental coding vulnerabilities.

3. **Reproducible benchmark corpus with ground truth.** No paper has assembled a labeled corpus of MCP servers with known vulnerability classes, permission scope measurements, and comparable risk scores. NeurIPS ED requires exactly this: a dataset + methodology that others can run, reproduce, and extend.

The OWASP MCP Top 10 and OWASP Agentic Top 10 (2026) provide qualitative risk categories. No paper has operationalised them into a scoring rubric and run it against a real-world corpus.

## Section 4 — Verification (April 30, 2026)

- arXiv:2506.13538 v5 (April 13, 2026) live-fetched. Abstract confirmed to retain aggregate-only reporting. No per-server scoring. No permission taxonomy. The April revision did not close the gap.
- arXiv:2603.10194 (March 2026) discovered and analyzed. Confirmed it uses generic CWEs, not an MCP-specific capability taxonomy, and its dataset is restricted to 222 Python servers. The novelty gap for a capability-based, multi-language benchmark of 500 servers remains open.
- Risk monitor: Cisco could publish their proprietary methodology before May 6. Less likely (enterprise vendors rarely publish scoring methods), but to be re-checked the day before submission.
