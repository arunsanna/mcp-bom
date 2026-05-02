"""Minimal reproducibility check: scan a fixture and diff against the golden output.

Used by `make reproduce`. Compares only path-independent fields so the golden
file is portable across machines and checkout locations.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp_bom.extractor import extract


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "extractor" / "tests" / "fixtures" / "dangerous_server"
GOLDEN = REPO_ROOT / "extractor" / "tests" / "fixtures" / "dangerous_server.golden.json"


def stable_subset(report_json: dict) -> dict:
    return {
        "server_id": report_json["server_id"],
        "capability_vector": report_json["capability_vector"],
        "score": report_json["score"],
        "languages_detected": report_json["languages_detected"],
    }


def main() -> int:
    report = extract(FIXTURE, server_id="dangerous_server")
    actual = stable_subset(report.model_dump(mode="json"))
    expected = stable_subset(json.loads(GOLDEN.read_text()))

    if actual == expected:
        print(f"OK  reproduction matches golden (score={actual['score']['attack_surface_score']})")
        return 0

    print("FAIL reproduction differs from golden", file=sys.stderr)
    print("--- expected", file=sys.stderr)
    print(json.dumps(expected, indent=2, sort_keys=True), file=sys.stderr)
    print("--- actual", file=sys.stderr)
    print(json.dumps(actual, indent=2, sort_keys=True), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
