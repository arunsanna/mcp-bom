#!/usr/bin/env python3
"""Pre-extract code signals for instrument-validation servers.

Lightweight regex scanner — does NOT import from extractor/.
Runs locally (macOS) to produce validation/labeling_signals/<id>.json.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request

REPO_ROOT = Path(__file__).resolve().parent.parent
VALIDATION_SET = REPO_ROOT / "validation" / "instrument_validation_set.json"
SIGNALS_DIR = REPO_ROOT / "validation" / "labeling_signals"
RAW_DIR = REPO_ROOT / "corpus" / "raw"
CACHED_LABELED = REPO_ROOT / "corpus" / "cached" / "labeled"
CACHED_OUTLIERS = REPO_ROOT / "corpus" / "cached" / "outliers"

SOURCE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".mjs", ".go", ".rs"}
MAX_EVIDENCE_PER_CATEGORY = 50
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
DOWNLOAD_TIMEOUT = 90

# ── regex patterns by category and language ──────────────────────────

PATTERNS: dict[str, dict[str, list[str]]] = {
    "tools_exposed": {
        "python": [
            r'@\w+\.tool|@app\.tool|mcp\.tool|@mcp_tool',
            r'tool\(name=|register_tool|add_tool',
        ],
        "ts": [
            r'\.tool\(\s*[\'"`]|server\.tool|registerTool|addTool',
        ],
        "go": [],
        "rust": [],
    },
    "env_reads": {
        "python": [
            r'os\.getenv\([\'"]([A-Z_][A-Z0-9_]*)[\'"]',
            r'os\.environ\.get\([\'"]([A-Z_][A-Z0-9_]*)[\'"]',
            r'os\.environ\[[\'"]([A-Z_][A-Z0-9_]*)[\'"]\]',
        ],
        "ts": [
            r'process\.env\.([A-Z_][A-Z0-9_]*)',
            r'process\.env\[[\'"]([A-Z_][A-Z0-9_]*)[\'"]\]',
        ],
        "go": [
            r'os\.Getenv\([\'"]([A-Z_][A-Z0-9_]*)[\'"]',
        ],
        "rust": [],
    },
    "file_ops": {
        "python": [
            r'\bopen\([\'"]|pathlib\.Path|shutil\.|os\.(remove|rename|mkdir|rmdir)',
        ],
        "ts": [
            r'fs\.(readFile|writeFile|readFileSync|writeFileSync|unlink|mkdir|rm)',
            r'fs/promises',
        ],
        "go": [
            r'os\.(Open|Create|ReadFile|WriteFile|Remove|Mkdir)',
        ],
        "rust": [],
    },
    "shell_calls": {
        "python": [
            r'\bsubprocess\.|os\.system\(|os\.popen\(|os\.execv',
        ],
        "ts": [
            r'child_process|execSync|spawnSync|spawn\(|exec\(',
        ],
        "go": [
            r'exec\.Command\(',
        ],
        "rust": [],
    },
    "http_endpoints": {
        "python": [
            r'@(app|router)\.(get|post|put|delete|patch)\([\'"]([^\'"]+)',
            r'@(\w+)\.route\([\'"]([^\'"]+)',
        ],
        "ts": [
            r'(app|router)\.(get|post|put|delete|patch)\([\'"]([^\'"]+)',
        ],
        "go": [
            r'http\.HandleFunc\([\'"]([^\'"]+)',
            r'\.Handle\([\'"]([^\'"]+)',
        ],
        "rust": [],
    },
}


def _lang_for_ext(ext: str) -> str:
    return {".py": "python", ".ts": "ts", ".tsx": "ts", ".js": "ts",
            ".mjs": "ts", ".go": "go", ".rs": "rust"}.get(ext, "")


def _resolve_archive_path(server_id: str, raw_archive_path: str) -> Path | None:
    """Find a local zip for this server."""
    # Direct zip path
    candidate = REPO_ROOT / "corpus" / raw_archive_path
    if candidate.exists() and candidate.suffix == ".zip":
        return candidate
    # Check cached locations
    for loc in [CACHED_LABELED, CACHED_OUTLIERS]:
        p = loc / (server_id + ".zip")
        if p.exists():
            return p
    return None


def _resolve_download_url(meta: dict) -> tuple[str | None, bool]:
    """Resolve a download URL from metadata (mirrors extractor logic).
    Returns (url, is_github_codeload) so caller can try master fallback.
    """
    repo_url = meta.get("repo_url", "")
    registry = meta.get("registry", "")
    name = meta.get("name", "")
    version = meta.get("version", "") or "latest"

    # GitHub / official with repo_url
    if repo_url:
        parts = repo_url.rstrip("/").split("/")
        if len(parts) >= 2:
            owner = parts[-2]
            repo = parts[-1].removesuffix(".git")
            return f"https://codeload.github.com/{owner}/{repo}/zip/main", True

    # npm
    if registry == "npm" and name:
        encoded = name.replace("/", "%2F")
        api_url = f"https://registry.npmjs.org/{encoded}/{version}"
        try:
            data = urlopen(Request(api_url), timeout=30).read()
            pkg = json.loads(data)
            tarball = pkg.get("dist", {}).get("tarball")
            if tarball:
                return tarball, False
        except Exception:
            pass

    # PyPI
    if registry == "pypi" and name:
        api_url = f"https://pypi.org/pypi/{name}/{version}/json" if version and version != "latest" else f"https://pypi.org/pypi/{name}/json"
        try:
            data = urlopen(Request(api_url), timeout=30).read()
            pkg = json.loads(data)
            for url_info in pkg.get("urls", []):
                if url_info.get("packagetype") == "sdist":
                    return url_info["url"], False
            if pkg.get("urls"):
                return pkg["urls"][0]["url"], False
        except Exception:
            pass

    return None, False


def _try_master_fallback(url: str) -> str | None:
    """For codeload.github.com URLs, try 'master' instead of 'main'."""
    if "codeload.github.com" in url and "/zip/main" in url:
        return url.replace("/zip/main", "/zip/master")
    return None


def _extract_archive_to_temp(archive_path: Path, tmpdir: str) -> list[Path]:
    """Extract zip or tarball, return list of source file paths."""
    files = []
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(tmpdir)
    except zipfile.BadZipFile:
        # Likely a tarball (PyPI sdist misnamed as .zip)
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                tf.extractall(tmpdir, filter="data")
        except Exception:
            print(f"    Cannot extract {archive_path}")
            return []
    for root, _, filenames in os.walk(tmpdir):
        for fn in filenames:
            p = Path(root) / fn
            if p.suffix in SOURCE_EXTENSIONS:
                files.append(p)
    return files


def _download_and_extract(url: str, tmpdir: str) -> list[Path]:
    """Download archive from URL and extract source files."""
    data = urlopen(Request(url), timeout=DOWNLOAD_TIMEOUT).read()
    if len(data) > MAX_ARCHIVE_BYTES:
        print(f"    WARNING: downloaded {len(data)} bytes, exceeds limit, skipping")
        return []

    files = []
    if url.endswith(".zip") or "codeload.github.com" in url:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(tmpdir)
    else:
        # Assume tarball (npm tgz, PyPI sdist)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(tmpdir, filter="data")

    for root, _, filenames in os.walk(tmpdir):
        for fn in filenames:
            p = Path(root) / fn
            if p.suffix in SOURCE_EXTENSIONS:
                files.append(p)
    return files


def _scan_file(fpath: Path, rel_path: str, tmpdir: str) -> dict[str, list[dict]]:
    """Scan a single source file, return evidence per category."""
    results: dict[str, list[dict]] = {cat: [] for cat in PATTERNS}
    lang = _lang_for_ext(fpath.suffix)
    if not lang:
        return results

    try:
        text = fpath.read_text(errors="replace")
    except Exception:
        return results

    lines = text.splitlines()
    for cat, lang_patterns in PATTERNS.items():
        patterns = lang_patterns.get(lang, [])
        for pat in patterns:
            try:
                compiled = re.compile(pat)
            except re.error:
                continue
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    results[cat].append({
                        "file": rel_path,
                        "line": i,
                        "snippet": line.strip()[:200],
                    })
    return results


def scan_server(server_id: str, raw_archive_path: str) -> dict:
    """Scan one server and return signals dict."""
    # Try local archive first
    archive = _resolve_archive_path(server_id, raw_archive_path)
    tmpdir = tempfile.mkdtemp(prefix=f"mcp-sig-{server_id}-")

    try:
        if archive:
            print(f"  Using local archive: {archive.name}")
            source_files = _extract_archive_to_temp(archive, tmpdir)
        else:
            # Load metadata and try downloading
            meta_path = REPO_ROOT / "corpus" / raw_archive_path
            if not meta_path.exists():
                print(f"  No archive and no metadata at {meta_path}")
                return _empty_result(server_id, 0, [])
            meta = json.loads(meta_path.read_text())
            url, is_github = _resolve_download_url(meta)
            if not url:
                print(f"  Cannot resolve download URL for {server_id}")
                return _empty_result(server_id, 0, [meta.get("language", "unknown")])
            print(f"  Downloading from: {url[:80]}...")
            try:
                source_files = _download_and_extract(url, tmpdir)
            except Exception as e:
                source_files = []
                if is_github:
                    master_url = _try_master_fallback(url)
                    if master_url:
                        print(f"  Retrying with master branch: {master_url[:80]}...")
                        try:
                            source_files = _download_and_extract(master_url, tmpdir)
                        except Exception as e2:
                            print(f"    Master branch also failed: {e2}")
                    else:
                        print(f"    Download failed: {e}")
                else:
                    print(f"    Download failed: {e}")

        if not source_files:
            print(f"  No source files found for {server_id}")
            return _empty_result(server_id, 0, [])

        # Compute relative paths
        rel_files = []
        for sf in source_files:
            try:
                rel = sf.relative_to(tmpdir)
                rel_files.append((sf, str(rel)))
            except ValueError:
                rel_files.append((sf, sf.name))

        # Scan all files
        merged: dict[str, list[dict]] = {cat: [] for cat in PATTERNS}
        langs = set()
        for sf, rel in rel_files:
            lang = _lang_for_ext(sf.suffix)
            if lang:
                langs.add(lang)
            hits = _scan_file(sf, rel, tmpdir)
            for cat in PATTERNS:
                merged[cat].extend(hits[cat])

        # Truncate per category
        for cat in PATTERNS:
            if len(merged[cat]) > MAX_EVIDENCE_PER_CATEGORY:
                truncated_count = len(merged[cat]) - MAX_EVIDENCE_PER_CATEGORY
                merged[cat] = merged[cat][:MAX_EVIDENCE_PER_CATEGORY]
                merged[cat].append({
                    "file": f"... ({truncated_count} more items truncated)",
                    "line": 0,
                    "snippet": "",
                })

        return {
            "server_id": server_id,
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            "categories": merged,
            "stats": {
                "total_files_scanned": len(source_files),
                "languages": sorted(langs),
            },
        }
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def _empty_result(server_id: str, file_count: int, langs: list[str]) -> dict:
    return {
        "server_id": server_id,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "categories": {cat: [] for cat in PATTERNS},
        "stats": {
            "total_files_scanned": file_count,
            "languages": sorted(langs),
        },
    }


def main():
    SIGNALS_DIR.mkdir(parents=True, exist_ok=True)

    with open(VALIDATION_SET) as f:
        val = json.load(f)

    servers = val["servers"]
    print(f"Processing {len(servers)} servers...")

    success = 0
    for i, s in enumerate(servers, 1):
        sid = s["server_id"]
        print(f"[{i}/{len(servers)}] {sid}")
        try:
            result = scan_server(sid, s["raw_archive_path"])
            out_path = SIGNALS_DIR / f"{sid}.json"
            out_path.write_text(json.dumps(result, indent=2))
            total_evidence = sum(len(v) for v in result["categories"].values())
            files_scanned = result["stats"]["total_files_scanned"]
            print(f"    -> {total_evidence} evidence items from {files_scanned} files")
            success += 1
        except Exception as e:
            print(f"    ERROR: {e}")
            # Write empty result so the app can still show the server
            result = _empty_result(sid, 0, [])
            out_path = SIGNALS_DIR / f"{sid}.json"
            out_path.write_text(json.dumps(result, indent=2))

    print(f"\nDone: {success}/{len(servers)} servers processed successfully")

    # Summary stats
    total_by_cat: dict[str, int] = {cat: 0 for cat in PATTERNS}
    for s in servers:
        sid = s["server_id"]
        sp = SIGNALS_DIR / f"{sid}.json"
        if sp.exists():
            data = json.loads(sp.read_text())
            for cat in PATTERNS:
                total_by_cat[cat] += len(data["categories"].get(cat, []))

    print("\nPer-category totals:")
    for cat, count in total_by_cat.items():
        print(f"  {cat}: {count}")


if __name__ == "__main__":
    main()
