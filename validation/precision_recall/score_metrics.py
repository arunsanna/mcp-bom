"""Compute precision/recall per category and Cohen's kappa from labels.

Inputs:
  predictions.json  extractor output (one row per server, per-category booleans)
  labels.json       human ground truth (one row per server, per-category booleans)

Output:
  metrics.md        markdown report with per-category precision/recall + kappa
                    + flags any rows where labels are still null (unlabeled).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRED = REPO_ROOT / "validation" / "precision_recall" / "predictions.json"
DEFAULT_LABELS = REPO_ROOT / "validation" / "precision_recall" / "labels.json"
DEFAULT_OUT = REPO_ROOT / "validation" / "precision_recall" / "metrics.md"

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


def confusion(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for p, l in pairs if p and l)
    fp = sum(1 for p, l in pairs if p and not l)
    fn = sum(1 for p, l in pairs if not p and l)
    tn = sum(1 for p, l in pairs if not p and not l)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def precision(c: dict) -> float | None:
    denom = c["tp"] + c["fp"]
    return c["tp"] / denom if denom else None


def recall(c: dict) -> float | None:
    denom = c["tp"] + c["fn"]
    return c["tp"] / denom if denom else None


def cohens_kappa(pairs: list[tuple[bool, bool]]) -> float | None:
    n = len(pairs)
    if n == 0:
        return None
    c = confusion(pairs)
    po = (c["tp"] + c["tn"]) / n
    p_pred_true = (c["tp"] + c["fp"]) / n
    p_label_true = (c["tp"] + c["fn"]) / n
    pe = p_pred_true * p_label_true + (1 - p_pred_true) * (1 - p_label_true)
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def fmt_pct(x: float | None) -> str:
    return f"{x*100:.1f}%" if x is not None else "n/a"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PRED)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    if not args.labels.exists():
        print(f"Labels file not found: {args.labels}")
        print("Edit validation/precision_recall/labels.template.json -> labels.json first.")
        return 1

    preds_by_id = {p["server_id"]: p["predictions"] for p in json.loads(args.predictions.read_text())}
    labels_rows = json.loads(args.labels.read_text())

    paired_per_cat: dict[str, list[tuple[bool, bool]]] = {c: [] for c in CATEGORIES}
    unlabeled_servers = []

    for row in labels_rows:
        sid = row["server_id"]
        labels = row["labels"]
        preds = preds_by_id.get(sid)
        if preds is None:
            continue
        if any(v is None for v in labels.values()):
            unlabeled_servers.append(sid)
            continue
        for cat in CATEGORIES:
            paired_per_cat[cat].append((bool(preds[cat]), bool(labels[cat])))

    n_labeled = len(labels_rows) - len(unlabeled_servers)

    try:
        preds_rel = args.predictions.relative_to(REPO_ROOT)
    except ValueError:
        preds_rel = str(args.predictions)

    try:
        labels_rel = args.labels.relative_to(REPO_ROOT)
    except ValueError:
        labels_rel = str(args.labels)

    lines = [
        "# Extractor precision/recall on ground-truth sample",
        "",
        f"- Predictions file: `{preds_rel}`",
        f"- Labels file: `{labels_rel}`",
        f"- Servers in labels file: {len(labels_rows)}",
        f"- Servers fully labeled: {n_labeled}",
        f"- Servers with at least one null label: {len(unlabeled_servers)}",
        "",
        "## Per-category results",
        "",
        "| Category | TP | FP | FN | TN | Precision | Recall | Cohen's kappa |",
        "|----------|----|----|----|----|-----------|--------|---------------|",
    ]

    overall_pairs: list[tuple[bool, bool]] = []
    for cat in CATEGORIES:
        pairs = paired_per_cat[cat]
        c = confusion(pairs)
        p = precision(c)
        r = recall(c)
        k = cohens_kappa(pairs)
        lines.append(
            f"| {cat} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | "
            f"{fmt_pct(p)} | {fmt_pct(r)} | {k:.3f}" if k is not None else
            f"| {cat} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | "
            f"{fmt_pct(p)} | {fmt_pct(r)} | n/a"
        )
        overall_pairs.extend(pairs)

    overall_k = cohens_kappa(overall_pairs)
    overall_c = confusion(overall_pairs)
    overall_p = precision(overall_c)
    overall_r = recall(overall_c)
    lines.append(
        f"| **overall** | {overall_c['tp']} | {overall_c['fp']} | {overall_c['fn']} | {overall_c['tn']} | "
        f"{fmt_pct(overall_p)} | {fmt_pct(overall_r)} | "
        + (f"{overall_k:.3f}" if overall_k is not None else "n/a")
    )

    lines += [
        "",
        "## Targets (issue #16)",
        "",
        "- precision >= 0.80 per category",
        "- recall >= 0.75 per category",
        "- Cohen's kappa >= 0.70 overall",
        "",
    ]

    if unlabeled_servers:
        lines += [
            "## Unlabeled servers",
            "",
            *(f"- {sid}" for sid in unlabeled_servers),
            "",
        ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(f"Wrote metrics report -> {args.output}")
    print(f"  fully labeled: {n_labeled}/{len(labels_rows)}")
    if overall_k is not None:
        print(f"  overall kappa: {overall_k:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
