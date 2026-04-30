# MCP-BOM

**A Reproducible Attack-Surface Benchmark for Model Context Protocol Servers**

Author: Arun Chowdary Sanna
Status: in development — targeting NeurIPS 2026 Evaluations & Datasets Track
Hard freeze: May 6, 2026 AoE

---

## What This Is

MCP-BOM is an automated tool and reproducible benchmark that, given an arbitrary Model Context Protocol (MCP) server, does two things no public work currently does together:

1. **Inventories** the server's declared capability and permission scope using a structured eight-category taxonomy.
2. **Scores** the server's attack surface as a numeric 0–100 value, with weights derived from OWASP Agentic Top 10 severity.

The deliverable is a labeled benchmark of 500 real-world public MCP servers from npm, PyPI, GitHub, and `mcp.run`, plus the open-source extractor and scoring methodology.

## Why This Exists

MCP is the default tool transport for production AI agents — 20 of 30 systems in the MIT 2025 AI Agent Index support it. The protocol does not enforce least privilege. Trend Micro identified 492 publicly exposed MCP servers with no auth or encryption. CVE-2025-6514 (`mcp-remote` RCE, CVSS 9.6) and CVE-2025-49596 (MCP Inspector CSRF→RCE, CVSS 9.4) demonstrate end-to-end compromise from untrusted endpoints. Hasan et al. (arXiv:2506.13538 v5) scanned 1,899 servers and reported aggregate health stats — but no per-server score and no permission taxonomy.

The OWASP MCP Top 10 and OWASP Agentic Top 10 (2026) define the qualitative risk categories. No published methodology operationalises them.

## The Genuine Gap

Three things have not been combined anywhere in the public literature or any peer-reviewed tool:

1. **Structured permission inventory.** No existing scanner maps MCP tool capabilities to a taxonomy of capability scopes (filesystem, shell, network, secrets, inter-server delegation, etc.).
2. **Numeric attack-surface score per server.** Industry tools (Cisco "dynamic risk scoring") exist but are proprietary. Hasan et al. report aggregate stats only.
3. **Reproducible benchmark with ground truth.** No paper assembles a labeled corpus of MCP servers with permission scope measurements and comparable risk scores.

Hasan et al. v5 was live-verified on April 30, 2026 to retain aggregate-only reporting. The novelty gate is clear.

## What's In This Repo

```
mcp-bom/
├── README.md                       this file
├── LICENSE                         Apache 2.0
├── CITATION.cff                    citation metadata
├── docs/
│   ├── prior-art-assessment.md     full landscape and gap statement
│   ├── capability-taxonomy.md      8-category permission spec
│   ├── score-function.md           0–100 scoring methodology
│   └── build-plan.md               six-day build plan to May 6
├── paper/
│   └── outline.md                  paper section structure
├── extractor/                      static extractor implementation (TBD May 2)
├── corpus/                         500-server benchmark manifest (TBD May 1)
└── validation/                     inter-rater + MCPLIB + CVE correlation (TBD May 4)
```

## Six-Day Build Plan

| Day | Date  | Work                                                                                  |
| --- | ----- | ------------------------------------------------------------------------------------- |
| 1   | May 1 | Scrape corpus; finalise capability taxonomy; freeze score function v1                 |
| 2   | May 2 | Build static extractor; run on first 100 servers; iterate on rules                    |
| 3   | May 3 | Run on full 500-server corpus; produce score distribution                             |
| 4   | May 4 | Validation suite (inter-rater + MCPLIB replay + CVE correlation); abstract submit AoE |
| 5   | May 5 | Paper draft (intro, methodology, results, related work); freeze repo                  |
| 6   | May 6 | Paper polish; full submission AoE                                                     |

## Methodology Summary

**Dataset**: top 500 public MCP servers stratified by install count, sourced from npm `@modelcontextprotocol`, PyPI, GitHub topic `mcp-server`, and `mcp.run` catalogue.

**Static extractor (layer 1)**: parses MCP `tools/list` schema and implementation source for API patterns matching the eight permission categories. Output is a capability scope vector per server.

**Score function (layer 2)**: weighted sum over capability vector with weights derived from OWASP Agentic Top 10 severity, plus independent components for capability breadth, privilege depth, exposure surface, and provenance. Normalised to 0–100.

**Optional dynamic layer (camera-ready extension)**: sandbox each server, observe declared-vs-actual tool call behavior, flag divergence as additional risk signal. Reuses MCPSecBench harness from companion AgentMesh project.

## Validation

- **Inter-rater reliability** on 50-server held-out subset (Cohen's κ).
- **MCPLIB attack replay** (31 attack types, arXiv:2508.12538) — high-score servers should fail more often.
- **CVE correlation** — known severe CVEs (CVE-2025-6514, CVE-2025-49596) should land at the high end of the score distribution.
- **Cross-source consistency** — same server packaged in multiple registries should score within tolerance.

## Related Work

| Tool / Paper                       | What It Does                                    | What It Misses                                         |
| ---------------------------------- | ----------------------------------------------- | ------------------------------------------------------ |
| Snyk Agent Scan (Invariant Labs)   | Detects malicious patterns in tool descriptions | No permission taxonomy, no numeric score               |
| Cisco AI Defense MCP Scanner       | YARA + LLM-as-judge + enterprise scoring        | Methodology private; open-source tier categorical only |
| Proximity (fr0gger)                | NOVA rules; flags categorical findings          | No score, no benchmark corpus                          |
| Hasan et al. (arXiv:2506.13538 v5) | 1,899-server static analysis, aggregate stats   | No per-server score, no permission taxonomy            |
| MCPLIB (arXiv:2508.12538)          | 31-attack taxonomy + simulation                 | No real-world corpus, no scoring                       |
| OWASP AIBOM Generator              | CycloneDX BOM for HF models, completeness score | No MCP coverage, no risk score                         |

Full prior-art assessment in `docs/prior-art-assessment.md`.

## Companion Work

- **Agent-BOM (ACM JRC)** — schema-level upstream; defines what to disclose at the agent level. MCP-BOM operationalises it at the MCP-server layer.
- **AgentMesh (ACM CCS Cycle B)** — OPA proxy + MCPSecBench evaluation harness; reusable for the dynamic validation layer.
- **OWASP AIBOM Generator** — natural reference-implementation host. Extending it to emit MCP-BOM output keeps the contribution inside OWASP.

## License

Apache 2.0. See `LICENSE`.

## Citation

See `CITATION.cff` for machine-readable metadata. Suggested human-readable citation:

```
Sanna, A. C. (2026). MCP-BOM: A Reproducible Attack-Surface Benchmark for
Model Context Protocol Servers. NeurIPS 2026 Evaluations & Datasets Track.
```
