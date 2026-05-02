"""Stratified-random sample selector for the precision/recall ground-truth set.

Picks N servers from corpus/manifest.json stratified by language so each group
gets fair representation. Uses a fixed seed so the sample is reproducible.

Usage:
    python validation/precision_recall/select_sample.py --n 30 --seed 1729
"""
from __future__ import annotations

import argparse
import json
import random
import zipfile
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "corpus" / "manifest.json"
RAW_DIR = REPO_ROOT / "corpus" / "raw"
DEFAULT_OUT = REPO_ROOT / "validation" / "precision_recall" / "sample.json"


def has_valid_archive(server: dict) -> bool:
    """Only servers whose source_archive_path resolves to a real, openable zip qualify.
    The corpus has many metadata-only stubs whose archive download failed; those
    cannot participate in static-analysis precision/recall.
    """
    rel = server.get("source_archive_path") or ""
    if not rel:
        return False
    p = RAW_DIR / Path(rel).name
    if not p.is_file():
        return False
    try:
        with zipfile.ZipFile(p) as zf:
            return bool(zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False

LANGUAGE_QUOTAS = {
    "python": 0.40,
    "typescript": 0.35,
    "javascript": 0.10,
    "go": 0.10,
    "other": 0.05,
}


def stratify(servers: list[dict], n: int, seed: int) -> list[dict]:
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for s in servers:
        lang = (s.get("language") or "other").lower()
        bucket = lang if lang in LANGUAGE_QUOTAS else "other"
        by_lang[bucket].append(s)

    rng = random.Random(seed)
    picked: list[dict] = []
    for bucket, quota in LANGUAGE_QUOTAS.items():
        target = max(1, round(n * quota))
        pool = by_lang.get(bucket, [])
        if not pool:
            continue
        rng.shuffle(pool)
        picked.extend(pool[:target])

    rng.shuffle(picked)
    return picked[:n]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    all_servers = manifest["servers"]
    servers = [s for s in all_servers if has_valid_archive(s)]
    print(f"Manifest: {len(all_servers)} entries; {len(servers)} have valid local archives")

    sample = stratify(servers, args.n, args.seed)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "n": len(sample),
        "seed": args.seed,
        "manifest_snapshot": manifest.get("snapshot_date"),
        "servers": sample,
    }, indent=2))
    print(f"Wrote {len(sample)} stratified servers -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
