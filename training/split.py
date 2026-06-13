"""
Stratified train/val/test split for the unified feature matrix.

Input : training/data_clean/features.parquet  (produced by TS extractor CLI)
Output: training/splits/train.parquet
        training/splits/val.parquet
        training/splits/test.parquet
        training/splits/test.lock.sha256   (commit this before any training)

Split ratio: 70 / 15 / 15
Stratification: by (label, _source) jointly — ensures every source
appears in every partition and class distribution is balanced.

Verification (all must pass before test.lock.sha256 is written):
  1. Zero hash overlap between any two partitions
  2. Class distribution per partition within ±2% of global
  3. Source distribution per partition within ±5% of global

Usage:
    python split.py [--input path/to/features.parquet] [--dry-run]
"""

import argparse
import hashlib
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

ROOT = Path(__file__).parent.parent
SPLITS_DIR = ROOT / "training" / "splits"
DEFAULT_INPUT = ROOT / "training" / "data_clean" / "features.parquet"

TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15
RANDOM_STATE = 42

CLASS_TOL = 0.02   # ±2% on class distribution
SOURCE_TOL = 0.05  # ±5% on source distribution


def row_hash(row: pd.Series) -> str:
    """Return the pre-computed _row_hash from unify.py if present,
    otherwise fall back to hashing path+query+body+label."""
    if "_row_hash" in row.index and row["_row_hash"]:
        return str(row["_row_hash"])
    key = (
        str(row.get("path", "")) + "|"
        + str(row.get("query", "")) + "|"
        + str(row.get("body", "") or "") + "|"
        + str(row.get("label", ""))
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def make_stratum_key(df: pd.DataFrame) -> pd.Series:
    """Combine label + _source into a single stratum key for stratification."""
    label = df["label"].astype(str)
    source = df["_source"].astype(str) if "_source" in df.columns else pd.Series(["unknown"] * len(df), index=df.index)
    return label + "||" + source


def stratified_split(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Two-stage split:
      Stage 1: Split off test (15%) from full dataset, stratified by (label, source).
      Stage 2: Split remaining 85% into train (70/85 ≈ 82.4%) and val (15/85 ≈ 17.6%).
    """
    strata = make_stratum_key(df)

    # --- Stage 1: carve out test ---
    sss1 = StratifiedShuffleSplit(
        n_splits=1, test_size=TEST_RATIO, random_state=RANDOM_STATE
    )
    trainval_idx, test_idx = next(sss1.split(df, strata))

    df_trainval = df.iloc[trainval_idx].reset_index(drop=True)
    df_test = df.iloc[test_idx].reset_index(drop=True)

    # --- Stage 2: split trainval into train and val ---
    val_frac_of_trainval = VAL_RATIO / (TRAIN_RATIO + VAL_RATIO)
    strata_tv = make_stratum_key(df_trainval)
    sss2 = StratifiedShuffleSplit(
        n_splits=1, test_size=val_frac_of_trainval, random_state=RANDOM_STATE
    )
    train_idx, val_idx = next(sss2.split(df_trainval, strata_tv))

    df_train = df_trainval.iloc[train_idx].reset_index(drop=True)
    df_val = df_trainval.iloc[val_idx].reset_index(drop=True)

    return df_train, df_val, df_test


def distribution(series: pd.Series) -> dict[str, float]:
    counts = series.value_counts(normalize=True)
    return counts.to_dict()


def check_distribution(
    global_dist: dict[str, float],
    part_dist: dict[str, float],
    tolerance: float,
    name: str,
    part_name: str,
) -> list[str]:
    errors = []
    for key, global_frac in global_dist.items():
        part_frac = part_dist.get(key, 0.0)
        diff = abs(part_frac - global_frac)
        if diff > tolerance:
            errors.append(
                f"  {part_name} {name} '{key}': "
                f"global={global_frac:.3f} partition={part_frac:.3f} "
                f"diff={diff:.3f} > tol={tolerance}"
            )
    return errors


def verify_no_overlap(
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    df_test: pd.DataFrame,
) -> list[str]:
    errors = []
    hashes_train = set(df_train.apply(row_hash, axis=1))
    hashes_val = set(df_val.apply(row_hash, axis=1))
    hashes_test = set(df_test.apply(row_hash, axis=1))

    for (name_a, h_a), (name_b, h_b) in [
        ("train", hashes_train), ("val", hashes_val),
    ], [
        ("train", hashes_train), ("test", hashes_test),
    ], [
        ("val", hashes_val), ("test", hashes_test),
    ]:
        overlap = h_a & h_b
        if overlap:
            errors.append(
                f"  {name_a} ∩ {name_b}: {len(overlap)} overlapping row hashes"
            )
    return errors


def write_test_lock(df_test: pd.DataFrame, output_dir: Path) -> Path:
    hashes = sorted(df_test.apply(row_hash, axis=1).tolist())
    combined = "\n".join(hashes)
    lock_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    lock_path = output_dir / "test.lock.sha256"
    lock_path.write_text(lock_hash + "\n", encoding="utf-8")
    return lock_path


def print_report(
    df: pd.DataFrame,
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    df_test: pd.DataFrame,
) -> None:
    print(f"\n{'='*60}")
    print("Split Report")
    print(f"{'='*60}")
    print(f"  Total rows : {len(df):,}")
    print(f"  Train      : {len(df_train):,}  ({len(df_train)/len(df)*100:.1f}%)")
    print(f"  Val        : {len(df_val):,}  ({len(df_val)/len(df)*100:.1f}%)")
    print(f"  Test       : {len(df_test):,}  ({len(df_test)/len(df)*100:.1f}%)")

    print("\n  Class distribution (label):")
    global_cls = distribution(df["label"])
    for label in sorted(global_cls):
        g = global_cls[label]
        tr = distribution(df_train["label"]).get(label, 0)
        v = distribution(df_val["label"]).get(label, 0)
        te = distribution(df_test["label"]).get(label, 0)
        print(f"    {label:15s}  global={g:.3f}  train={tr:.3f}  val={v:.3f}  test={te:.3f}")

    if "_source" in df.columns:
        print("\n  Source distribution (_source):")
        global_src = distribution(df["_source"])
        for src in sorted(global_src):
            g = global_src[src]
            tr = distribution(df_train["_source"]).get(src, 0)
            v = distribution(df_val["_source"]).get(src, 0)
            te = distribution(df_test["_source"]).get(src, 0)
            print(f"    {src:25s}  global={g:.3f}  train={tr:.3f}  val={v:.3f}  test={te:.3f}")


def run(input_path: Path, dry_run: bool = False) -> None:
    print(f"Loading {input_path} ...")
    df = pd.read_parquet(input_path)
    print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")

    required = {"label"}
    missing = required - set(df.columns)
    if missing:
        print(f"ERROR: missing required columns: {missing}")
        sys.exit(1)

    print("Splitting...")
    df_train, df_val, df_test = stratified_split(df)

    print_report(df, df_train, df_val, df_test)

    # --- Verification ---
    print(f"\n{'='*60}")
    print("Verification")
    print(f"{'='*60}")
    all_errors: list[str] = []

    # 1. Hash overlap
    print("  Checking hash overlap...")
    overlap_errors = verify_no_overlap(df_train, df_val, df_test)
    if overlap_errors:
        all_errors.extend(overlap_errors)
        for e in overlap_errors:
            print(f"  FAIL: {e}")
    else:
        print("  PASS: zero hash overlap between all partition pairs")

    # 2. Class distribution ±2%
    print("  Checking class distribution (±2%)...")
    global_cls = distribution(df["label"])
    for part_name, part_df in [("train", df_train), ("val", df_val), ("test", df_test)]:
        errs = check_distribution(global_cls, distribution(part_df["label"]), CLASS_TOL, "class", part_name)
        if errs:
            all_errors.extend(errs)
            for e in errs:
                print(f"  FAIL:{e}")
    if not any("class" in e for e in all_errors):
        print("  PASS: class distribution within ±2% in all partitions")

    # 3. Source distribution ±5%
    if "_source" in df.columns:
        print("  Checking source distribution (±5%)...")
        global_src = distribution(df["_source"])
        for part_name, part_df in [("train", df_train), ("val", df_val), ("test", df_test)]:
            errs = check_distribution(global_src, distribution(part_df["_source"]), SOURCE_TOL, "source", part_name)
            if errs:
                all_errors.extend(errs)
                for e in errs:
                    print(f"  FAIL:{e}")
        if not any("source" in e for e in all_errors):
            print("  PASS: source distribution within ±5% in all partitions")

    if all_errors:
        print(f"\n  {len(all_errors)} verification error(s). Splits NOT written.")
        sys.exit(1)

    if dry_run:
        print("\n[dry-run] Verification passed. No files written.")
        return

    # --- Write outputs ---
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)
    df_train.to_parquet(SPLITS_DIR / "train.parquet", index=False)
    df_val.to_parquet(SPLITS_DIR / "val.parquet", index=False)
    df_test.to_parquet(SPLITS_DIR / "test.parquet", index=False)

    lock_path = write_test_lock(df_test, SPLITS_DIR)
    print(f"\n  Written: train.parquet  ({len(df_train):,} rows)")
    print(f"  Written: val.parquet    ({len(df_val):,} rows)")
    print(f"  Written: test.parquet   ({len(df_test):,} rows)")
    print(f"  Written: {lock_path.name}")
    print(f"\n  *** COMMIT test.lock.sha256 TO GIT BEFORE ANY MODEL TRAINING ***")
    print(f"      SHA256: {lock_path.read_text().strip()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Stratified train/val/test split")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    run(args.input, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
