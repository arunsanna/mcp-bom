# MCP-BOM LLM Second Rater Protocol

## Purpose

Per pre-reg §4, a second annotator labels the 25-server overlap subset
of `validation/instrument_validation_set.json` for inter-rater
reliability (Cohen's κ). Per the locked decision in the project memory,
the second annotator is **Claude Sonnet 4.6**, acting as an independent
rater. The LLM rater blind-labels the overlap subset using the same
raw source archives and taxonomy definitions available to the human
annotator, but receives no extractor output, no labeling signals, and
no access to the human annotator's completed labels.

The resulting κ measures **human-vs-LLM agreement**, not human-vs-human
reliability. This limitation is documented as threat CnV-5 in
`docs/threats-to-validity.md`.

## Inputs the rater sees

- `validation/instrument_validation_overlap.json` — the 25-server
  overlap subset with server IDs, source, tier, and raw archive paths.
- For each server: the source archive at
  `/Volumes/A1/mcp-bom-storage/raw-archives/<server_id>.zip`.
  The rater reads source files from the archive directly.
- `docs/capability-taxonomy.md` — the eight-category definitions,
  detection patterns, sub-fields, and confidence levels. The rater uses
  the definitions verbatim as the labeling guide.

## Inputs the rater MUST NOT see

- `corpus/scored_code/<server_id>.json` — extractor verdicts.
- `validation/labels_arun.csv` — the human annotator's completed
  labels.
- `corpus/scored_code/_run_metrics.json` — aggregate prevalence
  statistics.
- `validation/labeling_signals/<server_id>.json` — signals shown to
  Arun via the labeling webapp. These are evidence-only (extracted
  code snippets, file paths), not classifications, but providing them
  to the LLM rater would create methodological asymmetry between the
  two rater paths. The LLM works from raw source only.

## Output

`validation/labels_annotator2.csv` with the same schema as
`labels_arun.csv`:

```
server_id,source,source_tier,raw_archive_path,filesystem,shell,egress,ingress,secrets,delegation,impersonation,data_sensitivity,notes
```

Each category cell is filled with `0` (not detected) or `1` (detected)
based on the rater's independent reading of the source archive. The
`notes` column must contain `file:line` evidence for every cell set to
`1`.

## Prompt template (verbatim — used by Task #10)

The following prompt is supplied to the LLM rater for each server:

```
You are an independent capability annotator for the MCP-BOM project.
Your task is to label a single MCP server's source archive across eight
capability categories. You must work from the source code only.

=== TAXONOMY DEFINITIONS (use verbatim) ===

[Insert the full text of docs/capability-taxonomy.md here.]

=== SERVER TO LABEL ===

Server ID: <server_id>
Source: <source>
Source archive path: <raw_archive_path>

Read ALL relevant source files in the archive. For each of the eight
categories below, determine whether the server's source code contains
evidence of that capability.

=== CATEGORIES ===

1. Filesystem — read, write, delete, or traverse local files.
2. Shell / Process Execution — execute commands, subprocess invocation,
   shell-out, unsafe deserialization/code evaluation.
3. Network Egress — outbound HTTP, raw socket, remote datastore clients.
4. Network Ingress — server bind interface, auth, TLS posture.
5. Secrets and Credentials — env var read, keychain, OAuth tokens,
   secret manager calls. NOTE: config-only reads (PORT, HOST, DEBUG)
   do NOT count. Only capability-secrets reads count (API_KEY, TOKEN,
   SECRET, credentials, etc.).
6. Inter-Server Delegation — calls to other MCP servers, MCP client
   SDK usage, A2A protocol, HTTP to /sse or /mcp endpoints.
7. Human Impersonation — email, messaging, calendar, social media
   posting on behalf of a user.
8. Data Egress Sensitivity — PII handling, PHI, financial data,
   location data, sensitive log content.

=== RULES ===

- You MUST NOT use any external tool, web search, or pre-existing
  analysis. Label only from the source code in the archive.
- For each category, output 0 (not detected) or 1 (detected).
- If you output 1, you MUST provide file:line evidence in the notes
  field (e.g., "src/index.ts:42: calls subprocess.run").
- If you are uncertain but there is plausible evidence, output 1 and
  note the uncertainty.
- Apply the taxonomy definitions strictly. Do not infer capabilities
  from README descriptions alone — look at actual source code.

=== OUTPUT FORMAT ===

Return exactly one CSV row (no header) with these columns in order:

server_id,filesystem,shell,egress,ingress,secrets,delegation,impersonation,data_sensitivity,notes

Example row:
my-server,1,0,1,0,1,0,0,0,"src/main.py:15: open(); src/api.py:88: requests.get(); .env.example:3: API_KEY"
```

## Procedural notes

- The prompt is executed once per server in the 25-server overlap set.
- The LLM rater receives no feedback between servers (no batch
  correction).
- Results are collected into `validation/labels_annotator2.csv` by the
  Task #10 automation.
- Cohen's κ is computed between `labels_arun.csv` and
  `labels_annotator2.csv` on the 25 overlap servers, per category and
  overall.
