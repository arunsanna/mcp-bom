# MCP-BOM Benchmark Corpus

Build target: Day 1 (May 1, 2026). 500 public MCP servers stratified by install count.

## Sources

- **npm**: `@modelcontextprotocol` org packages plus keyword search for `mcp-server`.
- **PyPI**: keyword search for `mcp` and `model-context-protocol`.
- **GitHub**: topic `mcp-server`, plus repos referenced in npm/PyPI metadata.
- **mcp.run**: catalogue scrape.

## Sampling

Stratified by install count to ensure ecological validity:

- Top 100 by npm/PyPI downloads (production-relevant).
- Random 100 from the long tail (typical of what an agent might install).
- 100 each from npm, PyPI, GitHub-only, and mcp.run-only buckets.

## Per-Server Manifest Fields

```json
{
  "id": "stable-slug",
  "name": "package-name",
  "version": "1.2.3",
  "language": "typescript",
  "registry": "npm",
  "install_count": 12345,
  "last_update": "2026-04-15",
  "repo_url": "https://github.com/...",
  "source_archive": "raw/<id>.tar.gz",
  "license": "MIT",
  "maintainer": "...",
  "signed": false
}
```

## Layout

```
corpus/
├── README.md
├── manifest.json               500-server stratified manifest (Day 1 output)
├── scored_500.json             extractor output + scores (Day 3 output)
├── raw/                        downloaded source archives (gitignored)
└── cache/                      registry metadata cache (gitignored)
```

## Reproducibility

The scrape script records the timestamp of each registry query and the exact metadata snapshot. Re-running the scrape with a different timestamp may produce a different population — version-pin the scrape with `--snapshot-date 2026-05-01`.

## Ethics and Safety

- All servers are scanned **statically only** in the v1 release. No live execution against third-party servers.
- Source archives are downloaded under each project's existing license (typically MIT/Apache).
- No private or paywalled servers in the corpus.
- Top-20 highest-score servers will be disclosed responsibly to maintainers before paper acceptance announcement.

## Status

Empty pending Day 1 scrape.
