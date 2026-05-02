# Extractor precision/recall on ground-truth sample

- Predictions file: `validation/precision_recall/predictions.json`
- Labels file: `validation/precision_recall/labels.draft.json`
- Servers in labels file: 27
- Servers fully labeled: 27
- Servers with at least one null label: 0

## Per-category results

| Category | TP | FP | FN | TN | Precision | Recall | Cohen's kappa |
|----------|----|----|----|----|-----------|--------|---------------|
| filesystem | 21 | 5 | 0 | 1 | 80.8% | 100.0% | 0.237
| shell | 1 | 19 | 0 | 7 | 5.0% | 100.0% | 0.027
| egress | 23 | 1 | 0 | 3 | 95.8% | 100.0% | 0.836
| ingress | 13 | 3 | 6 | 5 | 81.2% | 68.4% | 0.279
| secrets | 0 | 24 | 0 | 3 | 0.0% | n/a | -0.000
| delegation | 5 | 4 | 1 | 17 | 55.6% | 83.3% | 0.545
| impersonation | 2 | 15 | 1 | 9 | 11.8% | 66.7% | 0.014
| data_sensitivity | 7 | 12 | 3 | 5 | 36.8% | 70.0% | -0.005
| **overall** | 72 | 83 | 11 | 50 | 46.5% | 86.7% | 0.209

## Targets (issue #16)

- precision >= 0.80 per category
- recall >= 0.75 per category
- Cohen's kappa >= 0.70 overall

