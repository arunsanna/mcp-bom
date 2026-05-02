"""Print a labeling brief for each sampled server.

For each server in sample.json, extracts the zip and prints:
  - server id, repo_url, language
  - extractor's predictions (the row from predictions.json)
  - first 80 lines of README*
  - up to 250 lines combined from the main entry file(s) (server.py / index.ts /
    main.go / package.json's main / pyproject's [project.scripts])

The output is one big text block intended to be skimmed by a human reviewer (or
LLM acting as a second annotator) to decide each of the 8 capability labels.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE = REPO_ROOT / "validation" / "precision_recall" / "sample.json"
PRED = REPO_ROOT / "validation" / "precision_recall" / "predictions.json"
RAW = REPO_ROOT / "corpus" / "raw"

ENTRY_NAMES = (
    "server.py", "main.py", "__main__.py", "app.py",
    "index.ts", "server.ts", "main.ts", "index.js", "server.js",
    "main.go", "server.go",
)


def find_readme(root: Path) -> Path | None:
    for p in sorted(root.rglob("README*")):
        if p.is_file() and p.stat().st_size < 200_000:
            return p
    return None


def find_entries(root: Path) -> list[Path]:
    entries: list[Path] = []
    for name in ENTRY_NAMES:
        for p in sorted(root.rglob(name)):
            if p.is_file() and not any(part in {"node_modules", ".venv", "venv", "test", "tests", "__tests__"} for part in p.relative_to(root).parts):
                entries.append(p)
                if len(entries) >= 3:
                    return entries
    return entries


def head(text: str, n: int) -> str:
    lines = text.splitlines()
    return "\n".join(lines[:n])


def brief(server: dict, prediction: dict, raw_root: Path) -> str:
    sid = server["id"]
    zip_path = raw_root / Path(server["source_archive_path"]).name

    out: list[str] = []
    out.append("=" * 80)
    out.append(f"SERVER: {sid}")
    out.append(f"  repo: {server.get('repo_url')}")
    out.append(f"  lang: {server.get('language')}")
    out.append(f"  extractor predictions: {prediction['predictions']}")
    out.append(f"  extractor score: {prediction['score']}")
    out.append("")

    with tempfile.TemporaryDirectory() as t:
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(t)
        except zipfile.BadZipFile:
            out.append("  (bad zip)")
            return "\n".join(out)

        root = Path(t)
        # Most archives have a single top-level dir; descend if so
        children = [p for p in root.iterdir() if p.is_dir()]
        if len(children) == 1 and not any(p.is_file() for p in root.iterdir()):
            root = children[0]

        readme = find_readme(root)
        if readme:
            out.append(f"--- README ({readme.relative_to(root)}) ---")
            out.append(head(readme.read_text(errors="ignore"), 80))
        else:
            out.append("--- README missing ---")
        out.append("")

        entries = find_entries(root)
        if entries:
            for e in entries:
                out.append(f"--- ENTRY ({e.relative_to(root)}) ---")
                out.append(head(e.read_text(errors="ignore"), 120))
                out.append("")
        else:
            out.append("--- no entry file found ---")

        # also search for tool-decorator-style registrations
        tool_hits = []
        patterns = [
            r"@(?:mcp|server|tool|app)\.tool\b",
            r"\bnew\s+Tool\(",
            r"\bregisterTool\(",
            r"\bMCPTool\b",
            r"server\.setRequestHandler\(",
            r"\.tool\(['\"]",
        ]
        for src in list(root.rglob("*.py"))[:50] + list(root.rglob("*.ts"))[:50] + list(root.rglob("*.js"))[:50]:
            try:
                txt = src.read_text(errors="ignore")
            except Exception:
                continue
            for pat in patterns:
                for m in re.finditer(pat + r".{0,200}", txt):
                    tool_hits.append(f"  {src.relative_to(root)}: {m.group(0).strip()[:160]}")
                    if len(tool_hits) > 25:
                        break
            if len(tool_hits) > 25:
                break
        if tool_hits:
            out.append("--- exposed tools (decorators / registrations) ---")
            out.extend(tool_hits[:25])

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=Path, default=SAMPLE)
    ap.add_argument("--predictions", type=Path, default=PRED)
    ap.add_argument("--output", type=Path, default=REPO_ROOT / "validation" / "precision_recall" / "briefs.txt")
    ap.add_argument("--limit", type=int, default=0, help="brief only the first N servers (0=all)")
    args = ap.parse_args()

    sample = json.loads(args.sample.read_text())
    preds = {p["server_id"]: p for p in json.loads(args.predictions.read_text())}

    sections: list[str] = []
    servers = sample["servers"]
    if args.limit:
        servers = servers[: args.limit]

    for s in servers:
        if s["id"] not in preds:
            continue
        sections.append(brief(s, preds[s["id"]], RAW))

    args.output.write_text("\n".join(sections) + "\n")
    print(f"Wrote {len(sections)} briefs -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
