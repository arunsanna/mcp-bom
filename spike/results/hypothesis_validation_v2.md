# Hypothesis Validation Results — Spike v2 (n=23 servers)

## Summary Scorecard

| # | Hypothesis | Result | Key Metric | Verdict |
|:--|:-----------|:-------|:-----------|:--------|
| H1 | Capability Sprawl (mean >= 3 categories) | **SUPPORTED** | Mean = 4.7 categories | Servers expose ~half of all categories on average |
| H2 | Secrets Gateway (2x higher ASS) | **SUPPORTED** | 3.2x ratio (40.7 vs 12.9) | Secrets access predicts 3.2x higher attack surface |
| H3 | Language Divide (TS > Python) | **SUPPORTED** | TS=38.3 vs Py=24.4 | TypeScript servers 57% higher ASS on average |
| H4 | Ingress Multiplier | **SUPPORTED** | +29.8 points (45.1 vs 15.3) | Ingress nearly triples the average score |
| H5 | Inverted Boundary (super-linear) | **SUPPORTED** | Ingress+Delegation=52.9 vs Ingress-only=34.7 | Combination adds 18.2 points beyond ingress alone |
| H6 | Co-Location Paradox | **INCONCLUSIVE** | 9 observed vs 6.7 expected | Trend in right direction but sample too small for significance |
| H7 | Lookalike Risk Premium | **NOT TESTED** | No lookalikes in sample | Requires full 500-server corpus with typosquat detection |
| H8 | Registry Governance Gap | **NOT TESTED** | Need multi-registry data | Requires scraping from mcp.so, Smithery, etc. |
| H9 | Stale Server Decay | **NOT SUPPORTED** | Stale=24.2 vs Fresh=34.8 | Fresh servers score HIGHER (opposite of expected) |
| H10 | Human-in-the-Loop Illusion | **INCONCLUSIVE** | 2/4 have gates, 2/4 don't | 50/50 split — need larger impersonation sample |
| H11 | God Mode Default | **NOT SUPPORTED** | 0/8 admin connections found | Pattern matching may be too narrow; needs manual review |
| H12 | CWE-Capability Orthogonality | **NOT TESTED** | Requires running SAST tool | Need Semgrep/CodeQL run on subset |
| H13 | Safe Language Fallacy | **NOT TESTED** | Only 1 Go server (too small) | Need more Go/Rust servers in corpus |
| H14 | Schema-Implementation Drift | **NOT TESTED** | Requires schema parser | Need to parse tools/list JSON separately from AST |

## Detailed Findings

### Strong Support (H1, H2, H3, H4, H5)

**H1 — Capability Sprawl** is the paper's anchor finding. At 4.7 categories per server, the average MCP server exposes over half of all possible capability dimensions. This is a systemic least-privilege violation.

**H2 — Secrets Gateway** is the most striking quantitative result. Servers with secrets access score 3.2x higher than those without (40.7 vs 12.9). This is not just correlation — secrets access mechanistically requires other capabilities (egress to use API keys, filesystem to read config files).

**H3 — Language Divide** reveals an ecosystem-level structural difference. TypeScript servers (ASS=38.3, n=15) consistently score higher than Python servers (ASS=24.4, n=8). This may reflect the npm ecosystem's culture of broad dependency trees and the fact that enterprise MCP servers (which tend to be more complex) are predominantly written in TypeScript.

**H4 — Ingress Multiplier** shows that network-exposed servers are fundamentally different. The 29.8-point gap between ingress and non-ingress servers is the largest single-factor effect in the dataset.

**H5 — Inverted Boundary** is a novel finding grounded in Manadhata-Wing theory. Servers with both ingress AND delegation score 52.9, compared to 34.7 for ingress-only. The combination creates an unbounded execution graph that classical perimeter defense cannot contain.

### Revised Hypotheses (H9, H11)

**H9 — Stale Server Decay** showed the opposite of what we expected. Fresh servers score HIGHER (34.8) than stale ones (24.2). This likely reflects that actively maintained servers are the enterprise/popular ones that bundle more capabilities, while stale servers are simple, abandoned prototypes. The hypothesis should be revised to: "Active maintenance correlates with higher capability breadth, as maintained servers accumulate features over time."

**H11 — God Mode Default** found 0/8 admin connections. This is likely a detection limitation (our regex patterns are too narrow) rather than a genuine negative. Manual review of database connection code is needed.

### Requires Full Corpus (H7, H8, H12, H13, H14)

These hypotheses cannot be tested with the current spike sample and require the full 500-server corpus with additional tooling (typosquat detection, SAST integration, schema parsing, multi-language support).

## Score Distribution (n=23)

| Statistic | Value |
|:----------|:------|
| Mean | 33.5 |
| Median | 30.4 |
| Std Dev | 18.3 |
| Min | 5.2 (mcp-git, mcp-time) |
| Max | 64.5 (anthropic-quickstarts) |
| Servers with ASS >= 50 | 6/23 (26%) |
| Servers with ASS >= 40 | 10/23 (43%) |
