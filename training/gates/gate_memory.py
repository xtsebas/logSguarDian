"""
Fase 6, gate 4 — memory gate. Runs the existing benchmarks/onnx-memory.bench.js
against the candidate models via a temp directory (LOGSGUARDIAN_BENCH_MODEL_DIR
env var, Fase 6 change) — same temp-swap approach as the E2E gate, production
never touched. Gate criterion unchanged from F4.4: combined RSS <= 300MB.

The benchmark script itself always exits 0 and only prints a PASS/FAIL verdict
line — it predates having any automated caller, so this gate parses that line
rather than relying on its exit code (unlike the E2E gate, where jest's own
exit code is trustworthy).
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
BENCH_SCRIPT = REPO / "benchmarks" / "onnx-memory.bench.js"
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
            "details": {"error": "could not parse Total Delta RSS from benchmark output", "stdout_tail": "\n".join(result.stdout.splitlines()[-20:])},
        }

    total_delta_mb = float(match.group(1))
    passed = total_delta_mb <= RSS_GATE_MB

    return {
        "gate": "memory",
        "passed": passed,
        "details": {
            "total_delta_rss_mb": total_delta_mb,
            "gate_threshold_mb": RSS_GATE_MB,
            "margin_mb": round(RSS_GATE_MB - total_delta_mb, 2),
        },
    }
