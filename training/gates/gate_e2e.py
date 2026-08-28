"""
Fase 6, gate 3 — E2E gate. Runs the existing e2e/detection.test.ts suite
(the real F5.7 GATE PASS suite, unmodified) against the candidate models,
by pointing e2e/test-app.ts's model dir at a temp directory via the
LOGSGUARDIAN_E2E_MODEL_DIR env var (e2e/test-app.ts change, Fase 6) instead
of training/models/ — production is never read or written by this gate.

detection.test.ts already enforces the gate itself via real expect()
assertions (DETECTION_THRESHOLD=0.8 per class, FP_THRESHOLD=0.2 for
benign). Exit code alone is NOT trustworthy though: onnxruntime-node has a
known native-addon teardown crash under --forceExit (libc++abi ...
Napi::Error, seen repeatedly elsewhere in this project — plain
`pnpm run test:e2e`, packages/mlops/src/simulate-fleet.ts) that aborts the
process with a non-zero exit AFTER all tests already passed. So this gate
parses jest's own "Tests: N passed, N total" / "Test Suites: N passed, N
total" summary line instead of trusting returncode — a real test failure
changes that line's counts (or omits "passed" entirely), while the known
teardown crash does not.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
JEST_CONFIG = REPO / "e2e" / "jest.e2e.config.js"

TESTS_SUMMARY_RE = re.compile(r"Tests:\s+(\d+)\s+passed,\s+(\d+)\s+total")
SUITES_SUMMARY_RE = re.compile(r"Test Suites:\s+(\d+)\s+passed,\s+(\d+)\s+total")


def _all_passed(combined_output: str) -> bool:
    tests_match = TESTS_SUMMARY_RE.search(combined_output)
    suites_match = SUITES_SUMMARY_RE.search(combined_output)
    if not tests_match or not suites_match:
        return False
    tests_passed, tests_total = tests_match.groups()
    suites_passed, suites_total = suites_match.groups()
    return tests_passed == tests_total and suites_passed == suites_total


def check_e2e(candidate_rf_path, candidate_if_path) -> dict:
    with tempfile.TemporaryDirectory(prefix="lg-e2e-gate-") as tmp:
        model_dir = Path(tmp)
        shutil.copy(candidate_rf_path, model_dir / "rf.onnx")
        shutil.copy(candidate_if_path, model_dir / "if.onnx")

        result = subprocess.run(
            ["npx", "jest", "--config", str(JEST_CONFIG), "--forceExit"],
            cwd=REPO,
            env={**os.environ, "LOGSGUARDIAN_E2E_MODEL_DIR": str(model_dir)},
            capture_output=True, text=True,
        )

    combined = result.stdout + "\n" + result.stderr
    passed = _all_passed(combined)
    known_teardown_crash = result.returncode != 0 and passed

    return {
        "gate": "e2e",
        "passed": passed,
        "details": {
            "exit_code": result.returncode,
            "known_onnxruntime_teardown_crash_ignored": known_teardown_crash,
            "stdout_tail": "\n".join(result.stdout.splitlines()[-40:]),
            "stderr_tail": "\n".join(result.stderr.splitlines()[-40:]),
        },
    }
