# Contributing to MCP-BOM

Thank you for your interest in MCP-BOM! We welcome contributions that improve the benchmark, extractor, or documentation.

## Quick Start

```bash
# Clone and set up the development environment
git clone https://github.com/arunsanna/mcp-bom.git
cd mcp-bom
make install        # creates extractor/.venv and installs dev dependencies

# Run the full test suite
make test           # pytest with verbose output

# Full reproduction (install + test + golden-match)
make reproduce
```

## Development Workflow

### Branching

- **`main`** is the stable branch. All changes come in through pull requests.
- Create a feature branch from `main`:
  ```bash
  git checkout -b my-feature short-description
  ```
- Keep branches short-lived and focused on a single concern.

### Pull Requests

1. Open a PR against `main` with a clear description of the change.
2. Ensure `make test` passes locally before pushing.
3. Link any related issue (e.g., `Closes #42`).
4. Request a review and address feedback.

### Code Style

- **Python 3.12+** — type hints encouraged on public APIs.
- **Formatter:** [Black](https://github.com/psf/black) (default settings).
- **Linter:** [Ruff](https://github.com/astral-sh/ruff) — fix warnings before committing:
  ```bash
  ruff check extractor/ --fix
  ```
- Keep the public API surface minimal and documented.

### Commit Messages

- Use the [Conventional Commits](https://www.conventionalcommits.org/) style:
  ```
  feat: add network-scope capability parser
  fix: handle empty tools/list response gracefully
  docs: update score-function methodology
  ```

## Reporting Issues

- **Bug reports:** Use the [Bug Report](https://github.com/arunsanna/mcp-bom/issues/new?template=bug_report.md) template.
- **Feature requests:** Use the [Feature Request](https://github.com/arunsanna/mcp-bom/issues/new?template=feature_request.md) template.
- Include as much context as possible: Python version, OS, MCP server being tested, and steps to reproduce.

## Project Structure

```
mcp-bom/
├── extractor/       # Static extractor (Python package)
│   ├── src/mcp_bom/ # Core library code
│   └── tests/       # Unit and integration tests
├── corpus/          # 500-server benchmark manifest and metadata
├── validation/      # Inter-rater, MCPLIB replay, CVE correlation
├── docs/            # Taxonomy, score function, prior art, build plan
└── paper/           # NeurIPS submission draft
```

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).

## Contact

- **Author:** Arun Chowdary Sanna — [arun.sanna@ieee.org](mailto:arun.sanna@ieee.org)
- **Issues:** [GitHub Issues](https://github.com/arunsanna/mcp-bom/issues)
