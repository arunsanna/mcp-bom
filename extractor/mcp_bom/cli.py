from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_bom.extractor import extract
from mcp_bom.scorer import score_vector, load_weights
from mcp_bom.models import CapabilityVector, ProvenanceData, ExposureData


def cmd_scan(args: argparse.Namespace) -> None:
    source = Path(args.source).resolve()
    if not source.exists():
        print(f"Error: source not found: {source}", file=sys.stderr)
        sys.exit(1)

    report = extract(source, server_id=args.server_id or source.name)
    output_path = Path(args.output) if args.output else None

    report_json = report.model_dump(mode="json")
    text = json.dumps(report_json, indent=2)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        print(f"Wrote capability vector to {output_path}")
    else:
        print(text)


def cmd_score(args: argparse.Namespace) -> None:
    vector_path = Path(args.vector)
    weights_path = Path(args.weights)

    if not vector_path.exists():
        print(f"Error: vector file not found: {vector_path}", file=sys.stderr)
        sys.exit(1)
    if not weights_path.exists():
        print(f"Error: weights file not found: {weights_path}", file=sys.stderr)
        sys.exit(1)

    vector_data = json.loads(vector_path.read_text())

    if "capability_vector" in vector_data:
        cv_data = vector_data["capability_vector"]
    else:
        cv_data = vector_data

    vector = CapabilityVector(**cv_data)

    provenance = ProvenanceData()
    exposure = ExposureData()
    if "provenance" in vector_data:
        provenance = ProvenanceData(**vector_data["provenance"])
    if "exposure" in vector_data:
        exposure = ExposureData(**vector_data["exposure"])

    config = load_weights(weights_path)
    score = score_vector(vector, provenance, exposure, config=config)

    result = score.model_dump(mode="json")
    text = json.dumps(result, indent=2)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        print(f"Wrote score to {output_path}")
    else:
        print(text)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-bom",
        description="MCP-BOM static capability extractor and attack-surface scorer",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a server source for capabilities")
    scan_p.add_argument("--source", required=True, help="Path to server source (repo or directory)")
    scan_p.add_argument("--output", help="Output JSON path (default: stdout)")
    scan_p.add_argument("--server-id", help="Server identifier (default: directory name)")

    score_p = sub.add_parser("score", help="Score a capability vector")
    score_p.add_argument("--vector", required=True, help="Path to capability vector JSON")
    score_p.add_argument("--weights", required=True, help="Path to score_function.toml")
    score_p.add_argument("--output", help="Output JSON path (default: stdout)")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "score":
        cmd_score(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
