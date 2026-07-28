"""
Leave-One-Source-Out (LOSO) validation — PLAN.md task 3.6.

For each data source, trains an RF classifier on every OTHER source and
evaluates exclusively on the held-out source's full data (not the official
train/val/test split). This measures whether the model has learned
transferable attack patterns rather than source-specific artifacts.

Does not touch rf_v7.pkl or any production artifact — every model trained
here is throwaway, used only for the generalization measurement.
Feature extraction goes through the TS extractor CLI (R1); no feature
logic is reimplemented in Python.
"""
import json
import subprocess
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, classification_report

DATA_CLEAN = Path("training/data_clean")
MIN_HELDOUT_ROWS = 30

EXCLUDED_COLS = [
    "status_code", "req_count_1s", "req_count_5s",
    "req_count_60s", "error_rate_4xx_60s", "endpoint_diversity_60s",
]

SOURCES = sorted(
    f.stem for f in DATA_CLEAN.glob("*.jsonl")
    if f.stem != "unified" and not f.stem.startswith("_loso_")
)

print(f"Running LOSO for {len(SOURCES)} sources: {SOURCES}")

RESULTS = []

for held_out_source in SOURCES:
    print(f"\n{'='*60}")
    print(f"LOSO: holding out '{held_out_source}'")
    print(f"{'='*60}")

    train_without_path = DATA_CLEAN / f"_loso_train_without_{held_out_source}.jsonl"
    heldout_path = DATA_CLEAN / f"_loso_heldout_{held_out_source}.jsonl"
    train_features_path = DATA_CLEAN / f"_loso_train_features_{held_out_source}.csv"
    heldout_features_path = DATA_CLEAN / f"_loso_heldout_features_{held_out_source}.csv"

    try:
        with open(train_without_path, "w") as train_out, \
             open(heldout_path, "w") as heldout_out:
            for jsonl_file in DATA_CLEAN.glob("*.jsonl"):
                if jsonl_file.stem == "unified" or jsonl_file.stem.startswith("_loso_"):
                    continue
                with open(jsonl_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if jsonl_file.stem == held_out_source:
                            heldout_out.write(line + "\n")
                        else:
                            train_out.write(line + "\n")

        subprocess.run(
            ["node", "packages/extractor/dist/cli.js",
             str(train_without_path), str(train_features_path)],
            check=True,
        )
        subprocess.run(
            ["node", "packages/extractor/dist/cli.js",
             str(heldout_path), str(heldout_features_path)],
            check=True,
        )

        train_df = pd.read_csv(train_features_path)
        heldout_df = pd.read_csv(heldout_features_path)

        train_df = train_df.drop(columns=[c for c in EXCLUDED_COLS if c in train_df.columns])
        heldout_df = heldout_df.drop(columns=[c for c in EXCLUDED_COLS if c in heldout_df.columns])

        # sample_id/timestamp/_source/_row_hash are metadata, not model features.
        meta_cols = ["sample_id", "timestamp", "_source", "_row_hash"]
        train_df = train_df.drop(columns=[c for c in meta_cols if c in train_df.columns])
        heldout_df = heldout_df.drop(columns=[c for c in meta_cols if c in heldout_df.columns])

        if len(heldout_df) < MIN_HELDOUT_ROWS:
            print(f"  SKIP: {held_out_source} has too few rows ({len(heldout_df)}) for meaningful LOSO")
            continue

        y_train = train_df.pop("label")
        X_train = train_df
        y_heldout = heldout_df.pop("label")
        X_heldout = heldout_df

        rf_loso = RandomForestClassifier(
            n_estimators=30, max_depth=25,
            class_weight="balanced_subsample", random_state=42,
            n_jobs=-1,
        )
        rf_loso.fit(X_train, y_train)

        y_pred = rf_loso.predict(X_heldout)

        classes_in_heldout = sorted(y_heldout.unique())
        report = classification_report(
            y_heldout, y_pred,
            labels=classes_in_heldout,
            output_dict=True, zero_division=0,
        )

        macro_f1 = f1_score(
            y_heldout, y_pred, average="macro",
            labels=classes_in_heldout, zero_division=0,
        )

        print(f"  Held-out source: {held_out_source} ({len(heldout_df)} rows)")
        print(f"  Classes present: {classes_in_heldout}")
        print(f"  Macro F1 (LOSO): {macro_f1:.4f}")
        for cls in classes_in_heldout:
            if cls in report:
                print(f"    {cls}: F1={report[cls]['f1-score']:.4f} "
                      f"(support={report[cls]['support']})")

        RESULTS.append({
            "held_out_source": held_out_source,
            "n_rows": len(heldout_df),
            "classes": classes_in_heldout,
            "macro_f1": macro_f1,
            "per_class_f1": {
                cls: report[cls]["f1-score"]
                for cls in classes_in_heldout if cls in report
            },
        })
    finally:
        for p in [train_without_path, heldout_path, train_features_path, heldout_features_path]:
            p.unlink(missing_ok=True)

with open("training/models/loso_results.json", "w") as f:
    json.dump(RESULTS, f, indent=2)

print(f"\n{'='*60}")
print("LOSO SUMMARY")
print(f"{'='*60}")
for r in RESULTS:
    print(f"{r['held_out_source']:20} n={r['n_rows']:>7,} macro_f1={r['macro_f1']:.4f}")
