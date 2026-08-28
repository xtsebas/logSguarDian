#!/usr/bin/env python3
"""
Fase 5 of the CT/CI/CD pipeline — Continuous Training orchestrator.

Chains, in order: unify.py -> extractor CLI -> csv_to_parquet.py -> merge
curated telemetry (Fase 4's mlops review-clusters output) -> split.py (fresh
test.lock.sha256) -> train (notebooks 02-04) -> export ONNX + parity check
(notebook 05). Every step is an existing script — this file only sequences
them and handles the one genuinely new piece: candidate versioning.

Production models (training/models/rf.onnx, if.onnx) are backed up before
notebook 05 runs (it writes directly to those paths) and restored
immediately after — the freshly-trained models are saved under
*_candidate.onnx / *_candidate_<timestamp>.onnx instead. Production is
never left pointing at an unvalidated model; that only happens in Fase 8
(`mlops promote-canary`), after Fase 6's gates pass and Fase 7's canary
shadow run confirms the candidate is safe.

Any step failing aborts the run immediately; production models are
untouched either way (the backup/restore only brackets the training step).

Usage:
    python3 training/ct_pipeline.py --trigger manual
    python3 training/ct_pipeline.py --trigger volume --min-curated-rows 50
"""
import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

REPO = Path(__file__).parent.parent
TRAINING = REPO / "training"
DATA_CLEAN = TRAINING / "data_clean"
MODELS = TRAINING / "models"
EXTRACTOR_CLI = REPO / "packages" / "extractor" / "dist" / "cli.js"

UNIFIED = DATA_CLEAN / "unified.jsonl"
FEATURES_CSV = DATA_CLEAN / "features.csv"
FEATURES_PARQUET = DATA_CLEAN / "features.parquet"


def log(msg: str) -> None:
    print(f"[ct_pipeline] {msg}")


def run_step(name: str, cmd: list[str], cwd: Path = REPO) -> None:
    log(f"START {name}: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        log(f"FAILED {name} (exit {result.returncode}) — aborting, production models untouched.")
        sys.exit(1)
    log(f"OK {name}")


def count_curated_rows() -> int:
    total = 0
    for f in DATA_CLEAN.glob("telemetry_curated_*.jsonl"):
        with open(f, encoding="utf-8") as fh:
            total += sum(1 for line in fh if line.strip())
    return total


def merge_curated_telemetry() -> int:
    """Appends feature-space curated telemetry directly into features.parquet
    (post-extraction — there is no raw text for the extractor CLI to derive
    features from; see unify.py's EXCLUDED_PATTERNS comment for why these
    files never go through unify.py). Returns the number of rows merged."""
    curated_files = sorted(DATA_CLEAN.glob("telemetry_curated_*.jsonl"))
    if not curated_files:
        log("No telemetry_curated_*.jsonl files found — skipping merge.")
        return 0

    df = pd.read_parquet(FEATURES_PARQUET)

    rows = []
    for f in curated_files:
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                rec.setdefault("sample_id", f"telemetry_{rec.get('_row_hash', '')[:16]}")
                rec.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
                rows.append(rec)

    curated_df = pd.DataFrame(rows)
    for col in set(df.columns) - set(curated_df.columns):
        curated_df[col] = None
    curated_df = curated_df[df.columns]

    # unify.py's exact-dedup step (hash(path+query+body+label)) never runs on
    # this file — it's excluded there by design (see EXCLUDED_PATTERNS). Two
    # near-identical curated payloads (e.g. minor-perturbation variants of the
    # same injected pattern) can still produce colliding feature vectors, which
    # split.py's leakage check correctly rejects if they land in different
    # partitions — so dedup by _row_hash here, mirroring what unify.py does for
    # every other source.
    before = len(curated_df)
    curated_df = curated_df.drop_duplicates(subset="_row_hash", keep="first")
    dropped = before - len(curated_df)
    if dropped:
        log(f"Dropped {dropped} exact-duplicate curated row(s) by _row_hash before merging.")

    merged = pd.concat([df, curated_df], ignore_index=True)
    merged.to_parquet(FEATURES_PARQUET, index=False)
    log(f"Merged {len(curated_df)} curated telemetry rows into {FEATURES_PARQUET.name} (total now {len(merged)})")
    return len(curated_df)


def assert_clean_models_dir() -> None:
    """Refuses to run against a training/models/ with real uncommitted changes —
    restore_production_models() below reverts everything git-tracked in that
    directory, which would silently discard genuine unstaged work otherwise."""
    result = subprocess.run(
        ["git", "status", "--porcelain", str(MODELS)],
        cwd=REPO, capture_output=True, text=True,
    )
    if result.stdout.strip():
        log("training/models/ has uncommitted changes — commit or stash before running the CT pipeline:")
        log(result.stdout)
        sys.exit(1)


def _latest_metadata_file(prefix: str) -> Path | None:
    """Notebooks write rf_vN_metadata.json / if_vN_metadata.json with a
    hand-bumped version number, not auto-incremented — glob by mtime
    instead of guessing the current N."""
    candidates = sorted(MODELS.glob(f"{prefix}_v*_metadata.json"), key=lambda p: p.stat().st_mtime)
    return candidates[-1] if candidates else None


def save_candidates() -> dict[str, Path]:
    """Copies the notebooks' freshly-written rf.onnx/if.onnx (and their
    metadata JSONs, needed by Fase 6's metric gate) to a timestamped + a
    stable candidate filename, before production is restored."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    candidates: dict[str, Path] = {}
    for name in ("rf.onnx", "if.onnx"):
        stem = name.replace(".onnx", "")
        fresh = MODELS / name
        if not fresh.exists():
            continue
        timestamped = MODELS / f"{stem}_candidate_{ts}.onnx"
        stable = MODELS / f"{stem}_candidate.onnx"
        shutil.copy(fresh, timestamped)
        shutil.copy(fresh, stable)
        candidates[name] = stable
        log(f"Candidate saved: {timestamped.name} (and {stable.name})")

        metadata = _latest_metadata_file(stem)
        if metadata:
            metadata_stable = MODELS / f"{stem}_candidate_metadata.json"
            shutil.copy(metadata, metadata_stable)
            log(f"Candidate metadata saved: {metadata_stable.name} (from {metadata.name})")
    return candidates


def restore_production_models() -> None:
    """Reverts every git-tracked file under training/models/ to HEAD — covers
    rf.onnx/if.onnx, but also parity_report.json and any if_v*.pkl/metadata
    the notebooks version-bump and overwrite in place. Candidate files
    (*_candidate*.onnx) are untracked/gitignored, so this leaves them alone."""
    subprocess.run(["git", "checkout", "--", str(MODELS)], cwd=REPO, check=True)
    log("Restored training/models/ to HEAD — production untouched by this run.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trigger", choices=["manual", "volume"], default="manual")
    parser.add_argument("--min-curated-rows", type=int, default=50)
    args = parser.parse_args()

    if args.trigger == "volume":
        n = count_curated_rows()
        if n < args.min_curated_rows:
            log(f"Volume trigger: {n} curated rows < threshold {args.min_curated_rows} — nothing to do.")
            return
        log(f"Volume trigger: {n} curated rows >= threshold {args.min_curated_rows} — proceeding.")

    assert_clean_models_dir()
    t0 = time.time()

    run_step("unify", [sys.executable, str(TRAINING / "unify.py")])
    run_step("extractor CLI", ["node", str(EXTRACTOR_CLI), str(UNIFIED), str(FEATURES_CSV)])
    run_step("csv_to_parquet", [sys.executable, str(TRAINING / "csv_to_parquet.py")])

    merged_rows = merge_curated_telemetry()

    run_step("split", [sys.executable, str(TRAINING / "split.py")])

    try:
        run_step("train (notebooks 02-04)", [sys.executable, str(TRAINING / "run_notebooks.py")])
        run_step("export ONNX + parity (notebook 05)", [sys.executable, str(TRAINING / "run_notebook_05.py")])
    except SystemExit:
        # A step failed and already sys.exit(1)'d — restore production models
        # before propagating, in case notebook 05 partially overwrote them.
        restore_production_models()
        raise

    candidates = save_candidates()
    restore_production_models()

    elapsed = time.time() - t0
    log(f"\nCT pipeline completed in {elapsed:.1f}s")
    log(f"Curated telemetry rows merged: {merged_rows}")
    for name, path in candidates.items():
        log(f"Candidate: {path}")

    sys.path.insert(0, str(TRAINING / "gates"))
    from run_all_gates import run_all_gates  # noqa: E402

    log("\nRunning Fase 6 gates...")
    approved = run_all_gates(MODELS)
    if approved:
        log("Result: APPROVED_FOR_CANARY")
    else:
        log("Result: REJECTED — see gate report above for which gate failed and why.")
        sys.exit(1)


if __name__ == "__main__":
    main()
