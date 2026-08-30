#!/usr/bin/env python3
"""
csv_to_parquet.py — converts training/data_clean/features.csv
to training/data_clean/features.parquet.

Run after the TS extractor CLI produces features.csv.
Part of the retraining pipeline between extraction and split.
"""
import pandas as pd
from pathlib import Path

INPUT  = Path("training/data_clean/features.csv")
OUTPUT = Path("training/data_clean/features.parquet")

def main():
    print(f"Reading {INPUT}...")
    df = pd.read_csv(INPUT)
    print(f"Shape: {df.shape}")
    print(f"Columns (first 5): {list(df.columns[:5])}")
    print(f"Label distribution:")
    if 'label' in df.columns:
        print(df['label'].value_counts().to_string())

    print(f"\nWriting {OUTPUT}...")
    df.to_parquet(OUTPUT, index=False)

    # Verify round-trip
    verify = pd.read_parquet(OUTPUT)
    assert verify.shape == df.shape, \
        f"Round-trip shape mismatch: {verify.shape} != {df.shape}"
    print(f"Verified: {OUTPUT} ({OUTPUT.stat().st_size / 1024**2:.1f} MB)")
    print("Done.")

if __name__ == "__main__":
    main()
