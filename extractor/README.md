# MCP-BOM Static Extractor

Implementation of the MCP capability extractor and attack-surface scorer.

Build target: Day 2 (May 2, 2026).

## Layout (planned)

```
extractor/
├── README.md
├── pyproject.toml
├── score_function.toml         weights + depth tables (locked Day 1)
├── mcp_bom/
│   ├── __init__.py
│   ├── extractor.py            capability scope detection
│   ├── scorer.py               0–100 attack-surface score
│   ├── patterns/
│   │   ├── filesystem.py
│   │   ├── shell.py
│   │   ├── egress.py
│   │   ├── ingress.py
│   │   ├── secrets.py
│   │   ├── delegation.py
│   │   ├── impersonation.py
│   │   └── data_sensitivity.py
│   └── cli.py                  command-line entry point
└── tests/
    ├── fixtures/
    └── test_*.py
```

## Quick Use (planned)

```bash
mcp-bom scan --source <repo-or-tarball> --output capability_vector.json
mcp-bom score --vector capability_vector.json --weights score_function.toml
```

## Detection Strategy

Two-pass static analysis:

1. **AST pass** — parse source files (Python, TypeScript/JavaScript, Go) and walk the AST for direct API calls in the per-category pattern files.
2. **Schema pass** — parse the MCP `tools/list` output (or its source-declared equivalent) and apply heuristics on tool names, descriptions, and input schemas.

Confidence levels (`high` / `medium` / `low`) are recorded per detected category and feed into the score-function confidence multiplier.

## Dependencies (planned)

- Python 3.12+
- `tree-sitter` for multi-language AST parsing
- `pydantic` for schema validation
- `tomli` (or stdlib `tomllib`) for weights file
- `rich` for CLI output
- `pytest` for tests

## Status

Skeleton only. See `docs/build-plan.md` Day 2 for the implementation schedule.
