#!/usr/bin/env python3
"""Streaming corpus scan driver for MCP-BOM.

Downloads, scans, scores, and cleans up one server at a time.
Max N concurrent workers, per-host rate limiting, resumable.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

EXTRACTOR_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXTRACTOR_DIR.parent
sys.path.insert(0, str(EXTRACTOR_DIR))

from mcp_bom import __version__ as EXTRACTOR_VERSION
from mcp_bom.extractor import extract
from mcp_bom.scorer import load_weights

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
DOWNLOAD_TIMEOUT = 60
MAX_RETRIES = 3
PEAK_SAMPLE_INTERVAL = 30

CATEGORIES = [
    "filesystem",
    "shell",
    "egress",
    "ingress",
    "secrets",
    "delegation",
    "impersonation",
    "data_sensitivity",
]

ENTERPRISE_ORGS = {
    "anthropic", "cloudflare", "openai", "microsoft", "google", "aws",
    "stripe", "linear", "notion", "slack", "sentry", "supabase", "neon",
    "vercel", "netlify", "shopify", "gitlab", "datadog", "pagerduty",
    "atlassian", "salesforce", "mongodb", "redis", "elastic",
}


class TokenBucket:
    def __init__(self, rate: float):
        self.rate = rate
        self.tokens = rate
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            if time.monotonic() > deadline:
                return
            time.sleep(min(0.1, 1.0 / self.rate))


RATE_LIMITERS: dict[str, TokenBucket] = {}


def _get_limiter(host: str) -> TokenBucket:
    if host not in RATE_LIMITERS:
        if "github" in host:
            RATE_LIMITERS[host] = TokenBucket(5.0)
        elif "npmjs" in host:
            RATE_LIMITERS[host] = TokenBucket(1.0)
        elif "pypi" in host:
            RATE_LIMITERS[host] = TokenBucket(1.0)
        else:
            RATE_LIMITERS[host] = TokenBucket(2.0)
    return RATE_LIMITERS[host]


def _download_bytes(url: str, timeout: int = DOWNLOAD_TIMEOUT) -> bytes:
    parsed = urlparse(url)
    limiter = _get_limiter(parsed.hostname or "")
    limiter.acquire()

    headers = {"User-Agent": "mcp-bom-corpus-scanner/1.0"}
    if "github" in (parsed.hostname or "") and GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    req = Request(url, headers=headers)
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _download_with_retry(url: str, retries: int = MAX_RETRIES) -> bytes:
    last_exc = None
    for attempt in range(retries):
        try:
            return _download_bytes(url)
        except HTTPError as exc:
            last_exc = exc
            if exc.code == 404:
                raise
            if exc.code == 403:
                time.sleep(min(60, 2 ** (attempt + 3)))
            elif attempt < retries - 1:
                time.sleep(2 ** attempt)
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise last_exc  # type: ignore[misc]


def _resolve_github_url(server: dict) -> str | None:
    repo_url = server.get("repo_url", "")
    if "github.com" not in repo_url:
        return None
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        return None
    owner = parts[-2]
    repo = parts[-1].removesuffix(".git")
    return f"https://codeload.github.com/{owner}/{repo}/zip/main"


def _resolve_npm_url(server: dict) -> str | None:
    name = server.get("name", "")
    version = server.get("version", "") or "latest"
    if not name:
        return None
    encoded = name.replace("/", "%2F")
    api_url = f"https://registry.npmjs.org/{encoded}/{version}"
    try:
        data = _download_with_retry(api_url)
        pkg = json.loads(data)
        return pkg.get("dist", {}).get("tarball")
    except Exception:
        return None


def _resolve_pypi_url(server: dict) -> str | None:
    name = server.get("name", "")
    version = server.get("version", "")
    if not name:
        return None
    if version:
        api_url = f"https://pypi.org/pypi/{name}/{version}/json"
    else:
        api_url = f"https://pypi.org/pypi/{name}/json"
    try:
        data = _download_with_retry(api_url)
        pkg = json.loads(data)
        for url_info in pkg.get("urls", []):
            if url_info.get("packagetype") == "sdist":
                return url_info["url"]
        if pkg.get("urls"):
            return pkg["urls"][0]["url"]
    except Exception:
        pass
    return None


def resolve_download_url(server: dict) -> str | None:
    if _resolve_github_url(server):
        return _resolve_github_url(server)
    registry = server.get("registry", "")
    pkg_url = server.get("package_url", "")
    if registry == "npm" or "npmjs" in pkg_url:
        return _resolve_npm_url(server)
    if registry == "pypi" or "pypi.org" in pkg_url:
        return _resolve_pypi_url(server)
    if registry == "official" and server.get("repo_url"):
        return _resolve_github_url(server)
    return None


def _source_tier(server: dict) -> str:
    registry = server.get("registry", "")
    if registry == "official":
        return "official"
    maintainer = (server.get("maintainer", "") or "").lower()
    if maintainer in ENTERPRISE_ORGS:
        return "enterprise"
    repo_url = (server.get("repo_url", "") or "").lower()
    for org in ENTERPRISE_ORGS:
        if f"github.com/{org}/" in repo_url:
            return "enterprise"
    return "community"


def compute_labeled_ids(servers: list[dict], seed: int = 0x4D4250, n: int = 50) -> set[str]:
    by_registry: dict[str, list[dict]] = defaultdict(list)
    for s in servers:
        by_registry[s.get("registry", "unknown")].append(s)
    rng = random.Random(seed)
    labeled: set[str] = set()
    registries = sorted(by_registry.keys())
    per_reg = max(1, n // len(registries))
    for reg in registries:
        pool = list(by_registry[reg])
        rng.shuffle(pool)
        for s in pool[:per_reg]:
            labeled.add(s["id"])
    remaining = n - len(labeled)
    if remaining > 0:
        pool = [s for s in servers if s["id"] not in labeled]
        rng.shuffle(pool)
        for s in pool[:remaining]:
            labeled.add(s["id"])
    return labeled


_url_cache: dict[str, str | None] = {}
_url_cache_lock = threading.Lock()


def _cached_resolve(server: dict) -> str | None:
    sid = server["id"]
    with _url_cache_lock:
        if sid in _url_cache:
            return _url_cache[sid]
    url = resolve_download_url(server)
    with _url_cache_lock:
        _url_cache[sid] = url
    return url


def prefilter(
    servers: list[dict],
    output_dir: Path,
    val_dir: Path | None = None,
) -> tuple[list[dict], int, int]:
    if val_dir is None:
        val_dir = REPO_ROOT / "validation"
    val_dir.mkdir(parents=True, exist_ok=True)

    scannable_path = val_dir / "scannable_set.json"
    if scannable_path.exists():
        try:
            cached = json.loads(scannable_path.read_text())
            scannable_ids = set(cached.get("ids", []))
            remote_path = val_dir / "excluded_remote.json"
            no_source_path = val_dir / "excluded_no_source.json"
            remote = json.loads(remote_path.read_text()) if remote_path.exists() else []
            no_source = json.loads(no_source_path.read_text()) if no_source_path.exists() else []
            scannable = [s for s in servers if s["id"] in scannable_ids]
            return scannable, len(remote), len(no_source)
        except Exception:
            pass

    remote: list[dict] = []
    no_source: list[dict] = []
    scannable: list[dict] = []

    for s in servers:
        if s.get("language") == "remote":
            remote.append(s)
            continue
        if _cached_resolve(s) is None:
            no_source.append(s)
            continue
        scannable.append(s)

    (val_dir / "excluded_remote.json").write_text(json.dumps(
        [{"id": s["id"], "reason": "inherently_remote_no_source"} for s in remote], indent=2
    ))
    (val_dir / "excluded_no_source.json").write_text(json.dumps(
        [{"id": s["id"], "reason": "no_derivable_download_url", "registry": s.get("registry", "")} for s in no_source], indent=2
    ))
    scannable_path.write_text(json.dumps(
        {"total": len(scannable), "ids": [s["id"] for s in scannable]}, indent=2
    ))
    return scannable, len(remote), len(no_source)


def _extract_archive(archive_bytes: bytes, dest: Path, url: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if url.endswith(".tgz") or url.endswith(".tar.gz") or ".tar.gz?" in url:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            tf.extractall(dest, filter="data")
    elif url.endswith(".zip") or ".zip?" in url:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            zf.extractall(dest)
    else:
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
                tf.extractall(dest, filter="data")
        except tarfile.TarError:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                zf.extractall(dest)


def _find_source_root(extracted: Path) -> Path:
    entries = [p for p in extracted.iterdir() if p.is_dir() and p.name != "__MACOSX"]
    if len(entries) == 1:
        return entries[0]
    return extracted


def _vector_to_dict(report) -> dict:
    cv = report.capability_vector
    cats = cv.categories()
    result = {}
    for name, cat in cats.items():
        result[name] = {
            "detected": cat.detected,
            "confidence": cat.confidence.value if hasattr(cat.confidence, "value") else str(cat.confidence),
            "depth_raw": round(cat.depth_raw, 2),
            "depth_adjusted": round(cat.depth_adjusted, 2),
        }
    return result


def scan_single_server(
    server: dict,
    config: dict,
    temp_dir: Path,
    output_dir: Path,
    cache_dir: Path,
    labeled_ids: set[str],
    hold_dir: Path,
    sf_version: str,
) -> dict:
    sid = server["id"]
    scored_path = output_dir / f"{sid}.json"

    if scored_path.exists():
        try:
            existing = json.loads(scored_path.read_text())
            if (existing.get("extractor_version") == EXTRACTOR_VERSION
                    and existing.get("score_function_version") == sf_version):
                return {"status": "skipped", "id": sid}
        except Exception:
            pass

    url = _cached_resolve(server)
    if not url:
        return {"status": "error", "id": sid, "stage": "resolve", "error": "no_download_url"}

    t0 = time.monotonic()
    server_dir = temp_dir / sid
    archive_path = temp_dir / f"{sid}.archive"

    try:
        try:
            archive_bytes = _download_with_retry(url)
        except HTTPError as exc:
            if exc.code == 404 and "codeload.github.com" in url:
                fallback = url.replace("/zip/main", "/zip/master")
                archive_bytes = _download_with_retry(fallback)
            else:
                raise
        download_s = time.monotonic() - t0
        archive_size = len(archive_bytes)

        if archive_size > MAX_ARCHIVE_BYTES:
            _write_error(output_dir, sid, "download", "ArchiveExceeded",
                         f"Archive {archive_size} exceeds {MAX_ARCHIVE_BYTES} cap")
            return {
                "status": "oversized",
                "id": sid,
                "archive_size_bytes": archive_size,
                "download_seconds": round(download_s, 2),
            }

        archive_path.write_bytes(archive_bytes)

        t_extract = time.monotonic()
        _extract_archive(archive_bytes, server_dir, url)

        source_root = _find_source_root(server_dir)

        t_scan = time.monotonic()
        report = extract(str(source_root), server_id=sid)
        scan_s = time.monotonic() - t_scan

        result = {
            "id": sid,
            "registry": server.get("registry", ""),
            "language": server.get("language", ""),
            "source_tier": _source_tier(server),
            "archive_size_bytes": archive_size,
            "duration_s": round(time.monotonic() - t0, 2),
            "download_seconds": round(download_s, 2),
            "scan_seconds": round(scan_s, 2),
            "capability_vector": _vector_to_dict(report),
            "score": report.score.model_dump(mode="json"),
            "extractor_version": EXTRACTOR_VERSION,
            "score_function_version": sf_version,
        }

        _atomic_write(scored_path, result)

        if sid in labeled_ids:
            cache_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(archive_path, cache_dir / f"{sid}.zip")
        else:
            hold_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(archive_path, hold_dir / f"{sid}.zip")

        return {
            "status": "ok",
            "id": sid,
            "score": report.score.attack_surface_score,
            "archive_size_bytes": archive_size,
            "download_seconds": download_s,
            "scan_seconds": scan_s,
        }

    except Exception as exc:
        _write_error(output_dir, sid, "scan", type(exc).__name__, str(exc))
        return {"status": "error", "id": sid, "stage": "scan", "error": str(exc)}

    finally:
        if server_dir.exists():
            shutil.rmtree(server_dir, ignore_errors=True)
        if archive_path.exists():
            archive_path.unlink(missing_ok=True)


def _atomic_write(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.rename(path)


def _write_error(output_dir: Path, sid: str, stage: str, exc_type: str, message: str) -> None:
    error_line = json.dumps({
        "id": sid,
        "stage": stage,
        "exception_type": exc_type,
        "message": message,
        "traceback": traceback.format_exc(),
    })
    errors_path = output_dir / "_errors.jsonl"
    with open(errors_path, "a") as f:
        f.write(error_line + "\n")


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(int(len(s) * p / 100), len(s) - 1)
    return s[idx]


def _compute_metrics(
    start_time: datetime,
    end_time: datetime,
    manifest_total: int,
    pre_filtered_remote: int,
    pre_filtered_no_source: int,
    scannable_total: int,
    results: list[dict],
    sf_version: str,
    labeled_ids: set[str],
    cache_dir: Path,
    hold_dir: Path,
    output_dir: Path,
) -> dict:
    succeeded = [r for r in results if r.get("status") == "ok"]
    errored = [r for r in results if r.get("status") == "error"]
    skipped = [r for r in results if r.get("status") == "skipped"]

    dl_times = [r["download_seconds"] for r in succeeded if "download_seconds" in r]
    scan_times = [r["scan_seconds"] for r in succeeded if "scan_seconds" in r]
    sizes = [r["archive_size_bytes"] for r in succeeded if "archive_size_bytes" in r]

    scores = [r["score"] for r in succeeded if "score" in r]

    errors_by_stage: dict[str, int] = defaultdict(int)
    errors_by_type: dict[str, int] = defaultdict(int)
    for r in errored:
        stage = r.get("stage", "unknown")
        errors_by_stage[stage] += 1
    try:
        err_path = output_dir / "_errors.jsonl"
        if err_path.exists():
            for line in err_path.read_text().strip().split("\n"):
                if line.strip():
                    obj = json.loads(line)
                    errors_by_stage[obj.get("stage", "unknown")] += 1
                    errors_by_type[obj.get("exception_type", "unknown")] += 1
    except Exception:
        pass

    cap_prevalence: dict[str, float] = {}
    all_scores: list[float] = []
    all_sizes: list[int] = []
    all_dl_times: list[float] = []
    all_scan_times: list[float] = []
    det_counts: dict[str, int] = defaultdict(int)
    total_scored = 0

    for sp in output_dir.glob("*.json"):
        if sp.name.startswith("_"):
            continue
        try:
            d = json.loads(sp.read_text())
            ass = d.get("score", {}).get("attack_surface_score", 0)
            all_scores.append(ass)
            all_sizes.append(d.get("archive_size_bytes", 0))
            all_dl_times.append(d.get("download_seconds", 0))
            all_scan_times.append(d.get("scan_seconds", 0))
            total_scored += 1
            cv = d.get("capability_vector", {})
            for cat in CATEGORIES:
                if cv.get(cat, {}).get("detected"):
                    det_counts[cat] += 1
        except Exception:
            pass

    for cat in CATEGORIES:
        cap_prevalence[cat] = round(100 * det_counts.get(cat, 0) / max(total_scored, 1), 1)

    labeled_cached = len(list(cache_dir.glob("*.zip"))) if cache_dir.exists() else 0
    hold_cached = len(list(hold_dir.glob("*.zip"))) if hold_dir.exists() else 0

    git_hash = ""
    try:
        git_hash = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        pass

    return {
        "started_utc": start_time.isoformat(),
        "ended_utc": end_time.isoformat(),
        "total_duration_s": round((end_time - start_time).total_seconds(), 1),
        "manifest_total": manifest_total,
        "pre_filtered_remote": pre_filtered_remote,
        "pre_filtered_no_source": pre_filtered_no_source,
        "scannable_total": scannable_total,
        "scanned_succeeded": total_scored,
        "scanned_errored": len(errored),
        "scanned_skipped": len(skipped),
        "download_seconds_p50": round(_pct(all_dl_times, 50), 2),
        "download_seconds_p95": round(_pct(all_dl_times, 95), 2),
        "download_seconds_max": round(max(all_dl_times), 2) if all_dl_times else 0,
        "scan_seconds_p50": round(_pct(all_scan_times, 50), 2),
        "scan_seconds_p95": round(_pct(all_scan_times, 95), 2),
        "scan_seconds_max": round(max(all_scan_times), 2) if all_scan_times else 0,
        "archive_size_bytes_p50": int(_pct(all_sizes, 50)),
        "archive_size_bytes_p95": int(_pct(all_sizes, 95)),
        "archive_size_bytes_max": int(max(all_sizes)) if all_sizes else 0,
        "total_on_disk_bytes": int(sum(all_sizes)) if all_sizes else 0,
        "errors_by_stage": dict(errors_by_stage),
        "errors_by_exception_type": dict(errors_by_type),
        "score_distribution": {
            "min": round(min(all_scores), 1) if all_scores else 0,
            "p25": round(_pct(all_scores, 25), 1) if all_scores else 0,
            "median": round(_pct(all_scores, 50), 1) if all_scores else 0,
            "p75": round(_pct(all_scores, 75), 1) if all_scores else 0,
            "max": round(max(all_scores), 1) if all_scores else 0,
            "mean": round(sum(all_scores) / len(all_scores), 1) if all_scores else 0,
        },
        "capability_prevalence": cap_prevalence,
        "cached_subset_counts": {
            "labeled": labeled_cached,
            "hold_buffer": hold_cached,
        },
        "extractor_version": EXTRACTOR_VERSION,
        "score_function_version": sf_version,
        "git_hash": git_hash,
    }


def _peak_disk_monitor(temp_dir: Path, stop_event: threading.Event) -> list[int]:
    peaks: list[int] = []
    while not stop_event.is_set():
        try:
            total = sum(f.stat().st_size for f in temp_dir.rglob("*") if f.is_file())
            peaks.append(total)
        except Exception:
            pass
        stop_event.wait(PEAK_SAMPLE_INTERVAL)
    return peaks


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP-BOM streaming corpus scanner")
    parser.add_argument("--manifest", default="corpus/manifest.json")
    parser.add_argument("--score-function", default="score_function.toml")
    parser.add_argument("--output-dir", default="corpus/scored")
    parser.add_argument("--cache-dir", default="corpus/cached")
    parser.add_argument("--temp-dir", default="/tmp/mcp-bom-scan")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--ids", default=None)
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    sf_path = Path(args.score_function)
    output_dir = Path(args.output_dir)
    cache_dir = Path(args.cache_dir)
    temp_dir = Path(args.temp_dir)

    if not manifest_path.exists():
        print(f"Error: manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text())
    servers = manifest["servers"]
    config = load_weights(sf_path)
    sf_version = config.get("version", "unknown")

    print(f"Manifest: {len(servers)} servers")
    start_time = datetime.now(timezone.utc)

    scannable, n_remote, n_no_source = prefilter(servers, output_dir, val_dir=REPO_ROOT / "validation")
    print(f"Pre-filter: {n_remote} remote, {n_no_source} no-source → {len(scannable)} scannable")

    labeled_ids = compute_labeled_ids(servers)

    if args.ids:
        id_set = set(args.ids.split(","))
        scannable = [s for s in scannable if s["id"] in id_set]
        print(f"Filtered to {len(scannable)} specified IDs")

    if args.limit:
        scannable = scannable[: args.limit]
        print(f"Limited to {len(scannable)} servers")

    output_dir.mkdir(parents=True, exist_ok=True)
    labeled_cache = cache_dir / "labeled"
    outliers_cache = cache_dir / "outliers"
    errored_cache = cache_dir / "errored"
    hold_dir = temp_dir / "_hold"

    temp_dir.mkdir(parents=True, exist_ok=True)

    stop_event = threading.Event()
    peak_bytes: list[int] = []
    monitor_thread = threading.Thread(
        target=lambda: peak_bytes.extend(_peak_disk_monitor(temp_dir, stop_event)),
        daemon=True,
    )
    monitor_thread.start()

    results: list[dict] = []
    completed = 0
    total = len(scannable)

    print(f"Scanning {total} servers with {args.workers} workers...")
    print()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                scan_single_server,
                server,
                config,
                temp_dir,
                output_dir,
                labeled_cache,
                labeled_ids,
                hold_dir,
                sf_version,
            ): server
            for server in scannable
        }

        for future in as_completed(futures):
            server = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"status": "error", "id": server["id"], "stage": "executor", "error": str(exc)}
                _write_error(output_dir, server["id"], "executor", type(exc).__name__, str(exc))

            results.append(result)
            completed += 1

            status = result.get("status", "?")
            score_val = result.get("score", "")
            extra = f" ASS={score_val:.1f}" if isinstance(score_val, (int, float)) else ""
            print(f"  [{completed}/{total}] {result['id']} → {status}{extra}")

    stop_event.set()
    monitor_thread.join(timeout=5)

    print()
    print("Building outlier cache (top-20 by ASS)...")

    scored_files = sorted(output_dir.glob("*.json"))
    scored_servers: list[dict] = []
    for sf in scored_files:
        if sf.name.startswith("_"):
            continue
        try:
            d = json.loads(sf.read_text())
            scored_servers.append(d)
        except Exception:
            pass

    scored_servers.sort(key=lambda x: x.get("score", {}).get("attack_surface_score", 0), reverse=True)
    top_20 = scored_servers[:20]
    outliers_cache.mkdir(parents=True, exist_ok=True)
    for srv in top_20:
        hold_src = hold_dir / f"{srv['id']}.zip"
        if hold_src.exists():
            shutil.copy2(hold_src, outliers_cache / f"{srv['id']}.zip")
        else:
            print(f"  Re-downloading outlier: {srv['id']}")
            try:
                server_entry = next((s for s in scannable if s["id"] == srv["id"]), None)
                if server_entry:
                    url = _cached_resolve(server_entry)
                    if url:
                        try:
                            archive_bytes = _download_with_retry(url)
                        except HTTPError as exc:
                            if exc.code == 404 and "codeload.github.com" in url:
                                fallback = url.replace("/zip/main", "/zip/master")
                                archive_bytes = _download_with_retry(fallback)
                            else:
                                raise
                        (outliers_cache / f"{srv['id']}.zip").write_bytes(archive_bytes)
            except Exception as exc:
                print(f"  Warning: could not re-download {srv['id']}: {exc}")

    print("Building labeled cache...")
    labeled_cache.mkdir(parents=True, exist_ok=True)
    for sid in sorted(labeled_ids):
        if (labeled_cache / f"{sid}.zip").exists():
            continue
        server_entry = next((s for s in scannable if s["id"] == sid), None)
        if not server_entry:
            continue
        scored_path = output_dir / f"{sid}.json"
        if not scored_path.exists():
            continue
        url = _cached_resolve(server_entry)
        if not url:
            continue
        try:
            try:
                archive_bytes = _download_with_retry(url)
            except HTTPError as exc:
                if exc.code == 404 and "codeload.github.com" in url:
                    fallback = url.replace("/zip/main", "/zip/master")
                    archive_bytes = _download_with_retry(fallback)
                else:
                    raise
            (labeled_cache / f"{sid}.zip").write_bytes(archive_bytes)
        except Exception as exc:
            print(f"  Warning: could not cache labeled {sid}: {exc}")

    errored_cache.mkdir(parents=True, exist_ok=True)
    for r in results:
        if r.get("status") == "error":
            hold_src = hold_dir / f"{r['id']}.zip"
            err_json = {
                "id": r["id"],
                "stage": r.get("stage", "unknown"),
                "error": r.get("error", ""),
            }
            (errored_cache / f"{r['id']}.error.json").write_text(json.dumps(err_json, indent=2))

    print("Pruning hold buffer...")
    if hold_dir.exists():
        shutil.rmtree(hold_dir, ignore_errors=True)

    end_time = datetime.now(timezone.utc)

    metrics = _compute_metrics(
        start_time, end_time,
        manifest_total=len(servers),
        pre_filtered_remote=n_remote,
        pre_filtered_no_source=n_no_source,
        scannable_total=len(scannable),
        results=results,
        sf_version=sf_version,
        labeled_ids=labeled_ids,
        cache_dir=labeled_cache,
        hold_dir=hold_dir,
        output_dir=output_dir,
    )

    if peak_bytes:
        metrics["peak_temp_dir_bytes"] = max(peak_bytes)
    else:
        metrics["peak_temp_dir_bytes"] = 0

    _atomic_write(output_dir / "_run_metrics.json", metrics)

    n_labeled = len(list(labeled_cache.glob("*.zip")))
    n_outliers = len(list(outliers_cache.glob("*.zip")))
    n_errored = len(list(errored_cache.glob("*.error.json")))

    print()
    print("=" * 60)
    print("SUMMARY")
    print(f"  scannable: {metrics['scannable_total']} of {metrics['manifest_total']}")
    print(f"  scanned succeeded: {metrics['scanned_succeeded']}")
    print(f"  scanned errored: {metrics['scanned_errored']}")
    print(f"  scanned skipped: {metrics['scanned_skipped']}")
    elapsed = metrics['total_duration_s']
    h, rem = divmod(int(elapsed), 3600)
    m, s = divmod(rem, 60)
    print(f"  elapsed: {h}h {m}m {s}s")
    print(f"  peak disk during run: {metrics['peak_temp_dir_bytes'] / (1024**3):.2f} GB")

    print()
    print("DISTRIBUTION")
    sd = metrics.get("score_distribution", {})
    print(f"  ASS min/median/max: {sd.get('min', 0)}/{sd.get('median', 0)}/{sd.get('max', 0)}")
    print(f"  Top 10 highest ASS:")
    for i, srv in enumerate(top_20[:10], 1):
        sc = srv.get("score", {}).get("attack_surface_score", 0)
        print(f"    {i}. {srv['id']} — ASS={sc:.1f} ({srv.get('registry', '')})")

    print()
    print("CAPABILITY PREVALENCE (% of scanned):")
    cp = metrics.get("capability_prevalence", {})
    for cat in CATEGORIES:
        print(f"  {cat}: {cp.get(cat, 0)}%")

    if metrics.get("errors_by_stage"):
        print()
        print("ERRORS")
        for stage, count in sorted(metrics["errors_by_stage"].items(), key=lambda x: -x[1]):
            print(f"  {stage}: {count}")
        for etype, count in sorted(metrics["errors_by_exception_type"].items(), key=lambda x: -x[1])[:5]:
            print(f"  {etype}: {count}")

    print()
    print("CACHED SUBSETS")
    print(f"  labeled: {n_labeled} archives kept")
    print(f"  outliers: {n_outliers} archives kept")
    print(f"  errored: {n_errored} archives kept")

    print()
    print("PATHS")
    print(f"  per-server results: {output_dir}/*.json")
    print(f"  run metrics: {output_dir}/_run_metrics.json")
    print(f"  error log: {output_dir}/_errors.jsonl")
    print(f"  exclusions: validation/excluded_{{remote,no_source}}.json")

    try:
        branch = subprocess.check_output(["git", "branch", "--show-current"], stderr=subprocess.DEVNULL).decode().strip()
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL).decode().strip()
        print()
        print("GIT")
        print(f"  branch: {branch}, commit: {commit}")
    except Exception:
        pass

    print()
    ready = metrics["scanned_succeeded"] >= 100 and n_labeled >= 50
    deviation = metrics["scannable_total"] < 319
    print("NEXT-STEP READINESS")
    print(f"  pre-reg §4 instrument validation can begin: {'yes' if ready else 'no'}")
    print(f"  pre-reg deviation needed: {'yes' if deviation else 'no'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
