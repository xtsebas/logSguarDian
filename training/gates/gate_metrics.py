"""
Fase 6, gate 1 — metric gates. Reuses the exact thresholds already
established in this project (docs/decision-policy.md, PROJECT_CONTEXT.md),
does not invent new ones:

- RF: F1 >= 0.80 in at least 3/4 attack classes (Objetivo especifico 2;
  docs/decision-policy.md's F3.3 gate uses the same 0.80 bar).
- IF: recall >= 0.50 AND FP <= 0.06 — the stricter target adopted after
  if_v5's thin-margin lesson (FP=0.0811 missed the original 0.08 target by
  0.0011; docs/decision-policy.md section 2.3.2), not the original 0.10
  ceiling that's still the hard thesis-acceptance gate elsewhere in the
  same doc. The stricter number is what every retrain since if_v5 has
  actually been calibrated against (if_v9_metadata.json: FP=0.0574).

Metrics are read from the metadata JSON files the training notebooks write
alongside each candidate .pkl/.onnx (rf_v*_metadata.json, if_v*_metadata.json)
— never recomputed here, and never re-read from the notebook source itself
(the notebook is what drifted last time; the metadata JSON is the artifact
actually produced by whatever ran).
"""
import json
from pathlib import Path

RF_F1_THRESHOLD = 0.80
RF_MIN_CLASSES_PASSING = 3
IF_RECALL_THRESHOLD = 0.50
IF_FP_THRESHOLD = 0.06


def check_metrics(candidate_rf_metadata_path, candidate_if_metadata_path) -> dict:
    rf_meta = json.loads(Path(candidate_rf_metadata_path).read_text())
    if_meta = json.loads(Path(candidate_if_metadata_path).read_text())

    per_class_f1 = rf_meta["per_class_f1"]
    classes_passing = sum(1 for f1 in per_class_f1.values() if f1 >= RF_F1_THRESHOLD)
    rf_pass = classes_passing >= RF_MIN_CLASSES_PASSING

    if_recall = if_meta["val_recall"]
    if_fp = if_meta["val_fp_rate"]
    if_pass = if_recall >= IF_RECALL_THRESHOLD and if_fp <= IF_FP_THRESHOLD

    return {
        "gate": "metrics",
        "passed": bool(rf_pass and if_pass),
        "details": {
            "rf_per_class_f1": per_class_f1,
            "rf_classes_passing": classes_passing,
            "rf_min_classes_required": RF_MIN_CLASSES_PASSING,
            "rf_passed": rf_pass,
            "if_recall": if_recall,
            "if_recall_threshold": IF_RECALL_THRESHOLD,
            "if_fp_rate": if_fp,
            "if_fp_threshold": IF_FP_THRESHOLD,
            "if_passed": if_pass,
        },
    }
