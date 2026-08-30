"""
Fase 6, gate 4 — memory gate. Runs the REAL worker-pool architecture
benchmark (benchmarks/onnx-memory-pool.bench.js — spawns the actual
compiled worker.js via real worker_threads: 1 dedicated RF worker + 2 IF
pool workers, matching production exactly) against the candidate models,
via a temp directory (LOGSGUARDIAN_BENCH_MODEL_DIR env var) — same
temp-swap approach as the E2E gate, production never touched.

This gate previously called onnx-memory.bench.js, which loads RF+IF as two
plain InferenceSessions in the main thread — that does not replicate
production's real footprint (fixed onnxruntime-node native-init cost is
paid once per worker_thread, not once per process the way a single-thread
benchmark implies) and was confirmed during Fase 7's design investigation
to report a materially different, and wrong, number (an approximated
~177MB margin vs the real measured ~55MB on the documented baseline
machine). Fixed to measure what production will actually look like after
promotion: the real 1 RF + 2 IF worker-pool shape, with the CANDIDATE
models loaded instead of current production ones. Deliberately still the
non-canary pool benchmark, not the 4-worker canary variant — this gate
evaluates a candidate before any canary deployment decision, so it must
measure the shape production will have post-promotion (3 workers), not the
shape it would have during an active canary evaluation (4 workers, a
separate and already-documented tighter margin).

Gate criterion unchanged from F4.4: combined RSS <= 300MB.

The benchmark script itself always exits 0 and only prints a PASS/FAIL
verdict line — it predates having any automated caller, so this gate
parses that line rather than relying on its exit code (unlike the E2E
gate, where jest's own exit code is trustworthy).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
BENCH_SCRIPT = REPO / "benchmarks" / "onnx-memory-pool.bench.js"
RSS_GATE_MB = 300.0

TOTAL_DELTA_RE = re.compile(r"Total .* RSS.*:\s*([\d.]+)\s*MB")


def check_memory(candidate_rf_path, candidate_if_path) -> dict:
    with tempfile.TemporaryDirectory(prefix="lg-memory-gate-") as tmp:
        model_dir = Path(tmp)
        shutil.copy(candidate_rf_path, model_dir / "rf.onnx")
        shutil.copy(candidate_if_path, model_dir / "if.onnx")

        result = subprocess.run(
            ["node", str(BENCH_SCRIPT)],
            cwd=REPO,
            env={**os.environ, "LOGSGUARDIAN_BENCH_MODEL_DIR": str(model_dir)},
            capture_output=True, text=True,
        )

    match = TOTAL_DELTA_RE.search(result.stdout)
    if not match:
        return {
            "gate": "memory",
            "passed": False,
            "details": {"error": "could not parse Total RSS from benchmark output", "stdout_tail": "\n".join(result.stdout.splitlines()[-20:]), "stderr_tail": "\n".join(result.stderr.splitlines()[-20:])},
        }

    total_delta_mb = float(match.group(1))
    passed = total_delta_mb <= RSS_GATE_MB

    return {
        "gate": "memory",
        "passed": passed,
        "details": {
            "methodology": "real worker-pool (1 RF + 2 IF worker_threads, benchmarks/onnx-memory-pool.bench.js)",
            "total_rss_mb": total_delta_mb,
            "gate_threshold_mb": RSS_GATE_MB,
            "margin_mb": round(RSS_GATE_MB - total_delta_mb, 2),
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone runner for the memory gate — points at any directory containing rf.onnx/if.onnx (candidate or production).")
    parser.add_argument("--candidate-dir", type=Path, required=True)
    args = parser.parse_args()

    rf_path = args.candidate_dir / "rf.onnx"
    if_path = args.candidate_dir / "if.onnx"
    if not rf_path.exists() or not if_path.exists():
        print(f"error: rf.onnx/if.onnx not found in {args.candidate_dir}", file=sys.stderr)
        sys.exit(1)

    result = check_memory(rf_path, if_path)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)
