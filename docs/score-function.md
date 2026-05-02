# MCP-BOM Attack-Surface Score Function

> 0–100 numeric attack-surface score per MCP server. Weights derived from OWASP Agentic Top 10 (2026) severity. Locked v1 specification for the initial corpus run.

## Inputs

- Capability scope vector from the static extractor (eight categories with sub-fields and confidence levels).
- Provenance metadata: install count, last-update date, signed package (true/false), maintainer reputation.
- Exposure surface: ingress bind, auth, TLS.

## Construct

ASS measures **code-level attack surface** — the set of capabilities reachable
from any code path in the server's source code, regardless of whether the
capability is exposed via a registered MCP tool. This matches OWASP ASI05
(Unexpected Code Exec) and the Manadhare-surface formalism: an attacker
compromising the server (e.g., via prompt injection) can route through a tool
to any capability the source code touches.

The extractor's secondary `--scope tool` mode produces the "declared subset"
— capabilities reachable from inside MCP tool-handler functions only. The
difference between the two modes per server is the operational definition of
H14's schema-vs-implementation drift metric:

```
drift_categories(server) = code_scope_categories(server) - tool_scope_categories(server)
```

See **Capability Scope Vector** below for how the scope mode affects each
category's detection.

## Components

The final score is a weighted sum of four components, each normalised to 0–100, then combined with weights `w_b`, `w_d`, `w_e`, `w_p`.

### Component 1 — Capability Breadth (B)

How many of the eight permission categories are exposed.

```
B = (count_detected_categories / 8) * 100
```

### Component 2 — Privilege Depth (D)

For each detected category, how deep the privilege goes (read-only vs write vs execute). Per-category depth is capped at 10, summed across the eight categories, and normalised.

Depth scoring per category:

- Filesystem: read=2, write=5, delete=8, system-wide-scope=+2
- Shell: sandboxed=4, direct=8, unsafe-deserialization/code-evaluation=8, shell-interpreted=+1, arbitrary-args=+1
- Egress: allowlisted=2, fixed remote datastore=3, arbitrary-host=8
- Ingress: localhost=1, 0.0.0.0+auth=4, 0.0.0.0+no-auth=10
- Secrets: config-specific env read=2, arbitrary/exposed env read=6, keychain-read=6, cloud-KMS-read=8, write=+2
- Delegation: static=3, dynamic=7
- Impersonation: per-channel +3, no-approval-gate=+3
- Data-sensitivity: none=0, financial/location=4, PII=7, PHI=9

```
D = (sum of detected category depths / 80) * 100
```

### Component 3 — Exposure Surface (E)

How reachable the server is from outside the host.

- Localhost-only, auth required, TLS = 0
- Localhost-only, no auth = 20
- Public bind, auth + TLS = 40
- Public bind, auth no TLS = 60
- Public bind, no auth + TLS = 80
- Public bind, no auth, no TLS = 100

### Component 4 — Provenance (P)

Inverse trust signal — lower trust raises the score.

- signed package + active maintenance + 1k+ install = 0
- signed package + stale (>180 days) = 25
- unsigned + active maintenance = 35
- unsigned + stale = 60
- single-author + sub-100 installs + stale = 80
- typosquat suspicion or new account = 100

### Combined Score

```
ASS = w_b * B + w_d * D + w_e * E + w_p * P
```

Locked v1 weights (sum to 1.0):

- w_b = 0.20 (breadth)
- w_d = 0.45 (depth)
- w_e = 0.20 (exposure)
- w_p = 0.15 (provenance)

Rationale: depth dominates because a single high-privilege capability is more dangerous than many low-privilege ones. Provenance is weighted lowest because it is recoverable (a stale repo can become active) while depth is intrinsic.

## Capability Scope Vector

Each of the eight categories is detected via two independent layers:

1. **Source-code patterns** — regex and AST analysis of `.py`, `.ts`, `.js`, `.go` files. Scope-gated: `--scope code` scans all source; `--scope tool` restricts to MCP tool-handler context.
2. **Schema property patterns** — JSON schema property names (e.g. `"path"`, `"command"`, `"url"`, `"api_key"`) that indicate a tool parameter referencing a capability. This layer runs regardless of `--scope`.

Schema-only detections produce `confidence: low` and are tracked separately in the drift metric.

## Confidence Adjustment

Detected categories with `low` confidence contribute 50% of their depth value. Categories with `medium` confidence contribute 75%. `high` confidence contributes 100%.

Confidence adjustment applies to privilege depth only. Breadth still counts a category as detected when confidence is `low`, `medium`, or `high`; validation reports precision/recall separately so low-confidence detections can be audited.

## OWASP Agentic Top 10 Mapping

For traceability and discussion, each capability category maps to OWASP Agentic Top 10 risks:

| Capability       | OWASP Agentic Top 10                                               |
| ---------------- | ------------------------------------------------------------------ |
| Filesystem       | ASI02 Tool Misuse, ASI05 Unexpected Code Exec                      |
| Shell            | ASI05 Unexpected Code Exec, ASI02 Tool Misuse                      |
| Network egress   | ASI04 Supply Chain, ASI06 Memory Poisoning                         |
| Network ingress  | ASI03 Identity & Privilege Abuse, ASI10 Rogue Agents               |
| Secrets          | ASI03 Identity & Privilege Abuse, ASI04 Supply Chain               |
| Delegation       | ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures |
| Impersonation    | ASI09 Human-Agent Trust Exploitation                               |
| Data sensitivity | ASI06 Memory Poisoning, ASI04 Supply Chain                         |

## Validation Targets

The score function is calibrated such that:

- CVE-2025-6514 (`mcp-remote` RCE) → ASS ≥ 80
- CVE-2025-49596 (MCP Inspector CSRF→RCE) → ASS ≥ 80
- A localhost-only filesystem-read-only server with active maintenance → ASS ≤ 30
- An MCP server bound to 0.0.0.0 with no auth and shell execution → ASS ≥ 90

If the v1 weights produce mis-rankings against these calibration targets, weights are re-tuned via grid search constrained to validation expectations.

## Reproducibility

- Weights, depth tables, and confidence multipliers are checked into this repo as `score_function.toml`.
- Score function is a pure function: `(capability_vector, provenance, exposure) -> 0-100`. Deterministic across runs.
- Recomputation: `python -m mcp_bom.scorer --vector <path> --weights score_function.toml`.
