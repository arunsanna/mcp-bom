"""Run the extractor over the sampled servers and emit a labeling worksheet.

For each sampled server:
  1. Unzip its source archive into a temp dir.
  2. Run the extractor.
  3. Record the predicted detection per category (boolean).

The output is two files:
  - predictions.json   ground-truth-side comparison input (predictions only)
  - labels.template.json   a per-server labels template the human PI fills in
                           (set each category to true/false/null)

Usage:
    python validation/precision_recall/generate_worksheet.py
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import traceback
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "extractor"))

from mcp_bom.extractor import extract  # noqa: E402

DEFAULT_SAMPLE = REPO_ROOT / "validation" / "precision_recall" / "sample.json"
DEFAULT_PRED = REPO_ROOT / "validation" / "precision_recall" / "predictions.json"
DEFAULT_LABELS = REPO_ROOT / "validation" / "precision_recall" / "labels.template.json"

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


def predict_one(zip_path: Path, server_id: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(tmpdir)
        except zipfile.BadZipFile:
            return {"error": "bad_zip"}

        report = extract(Path(tmpdir), server_id=server_id)
        cv = report.capability_vector
        return {
            "predictions": {cat: getattr(cv, cat).detected for cat in CATEGORIES},
            "score": report.score.attack_surface_score,
            "languages": [l.value for l in report.languages_detected],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--predictions-out", type=Path, default=DEFAULT_PRED)
    parser.add_argument("--labels-template-out", type=Path, default=DEFAULT_LABELS)
    args = parser.parse_args()

    sample = json.loads(args.sample.read_text())
    servers = sample["servers"]

    predictions = []
    labels_template = []
    raw_dir = REPO_ROOT / "corpus" / "raw"

    for i, s in enumerate(servers, 1):
        sid = s["id"]
        zip_path = raw_dir / Path(s["source_archive_path"]).name
        if not zip_path.exists():
            print(f"  [{i}/{len(servers)}] {sid}: archive missing ({zip_path})")
            continue

        try:
            result = predict_one(zip_path, sid)
        except Exception:
            print(f"  [{i}/{len(servers)}] {sid}: extractor error")
            traceback.print_exc()
            continue

        if "error" in result:
            print(f"  [{i}/{len(servers)}] {sid}: {result['error']}")
            continue

        predictions.append({
            "server_id": sid,
            "language": s.get("language"),
            "repo_url": s.get("repo_url"),
            "predictions": result["predictions"],
            "score": result["score"],
        })

        labels_template.append({
            "server_id": sid,
            "repo_url": s.get("repo_url"),
            "labels": {cat: None for cat in CATEGORIES},
            "notes": "",
        })
        print(f"  [{i}/{len(servers)}] {sid}: score={result['score']:.1f}")

    args.predictions_out.parent.mkdir(parents=True, exist_ok=True)
    args.predictions_out.write_text(json.dumps(predictions, indent=2))
    if not args.labels_template_out.exists():
        args.labels_template_out.write_text(json.dumps(labels_template, indent=2))
        print(f"Wrote labels TEMPLATE -> {args.labels_template_out}")
    else:
        print(f"Skipped overwriting existing labels file -> {args.labels_template_out}")

    print(f"Wrote {len(predictions)} predictions -> {args.predictions_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
