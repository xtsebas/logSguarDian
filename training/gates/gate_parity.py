"""
Fase 6, gate 2 — parity gate. Reuses export_parity_fixture.py's approach
(synthetic float32 inputs, N=100, random_state=42 — a pure runtime-parity
check, not tied to any real feature semantics) against the CANDIDATE models
instead of production, then hands the fixture to parity_check_node.js to
verify onnxruntime-node agrees with onnxruntime (Python) within the same
1e-5 tolerance packages/core/tests/parity.node.test.ts uses for production.

This is deliberately a different check than notebook 05's own internal
assert (sklearn vs Python onnxruntime) — it catches Node-binding-specific
discrepancies that a Python-only check cannot see, on the actual runtime
production code uses.
"""
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

REPO = Path(__file__).parent.parent.parent
GATES_DIR = Path(__file__).parent
PARITY_CHECK_NODE = GATES_DIR / "parity_check_node.js"

N_SAMPLES = 100
RANDOM_STATE = 42
RF_OUTPUT_IDX = 1
IF_OUTPUT_IDX = 1


def _build_fixture(rf_path, if_path, n_rf_features: int, n_if_features: int) -> dict:
    rng = np.random.RandomState(RANDOM_STATE)
    rf_inputs = rng.rand(N_SAMPLES, n_rf_features).astype(np.float32)
    if_inputs = rng.rand(N_SAMPLES, n_if_features).astype(np.float32)

    rf_sess = ort.InferenceSession(str(rf_path))
    if_sess = ort.InferenceSession(str(if_path))

    rf_expected, if_expected = [], []
    for i in range(N_SAMPLES):
        rf_out = rf_sess.run(None, {"float_input": rf_inputs[i : i + 1]})
        if_out = if_sess.run(None, {"float_input": if_inputs[i : i + 1]})
        rf_expected.append(rf_out[RF_OUTPUT_IDX][0].tolist())
        if_expected.append(float(if_out[IF_OUTPUT_IDX][0][0]))

    return {
        "rf_inputs": rf_inputs.tolist(),
        "if_inputs": if_inputs.tolist(),
        "rf_expected": rf_expected,
        "if_expected": if_expected,
    }


def check_parity(candidate_rf_path, candidate_if_path, n_rf_features: int, n_if_features: int, tmp_dir: Path) -> dict:
    fixture = _build_fixture(candidate_rf_path, candidate_if_path, n_rf_features, n_if_features)
    fixture_path = Path(tmp_dir) / "candidate_parity_fixture.json"
    fixture_path.write_text(json.dumps(fixture))

    result = subprocess.run(
        ["node", str(PARITY_CHECK_NODE), str(candidate_rf_path), str(candidate_if_path), str(fixture_path)],
        cwd=REPO, capture_output=True, text=True,
    )

    try:
        node_result = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {
            "gate": "parity",
            "passed": False,
            "details": {"error": "parity_check_node.js did not produce parseable output", "stdout": result.stdout, "stderr": result.stderr},
        }

    return {
        "gate": "parity",
        "passed": bool(node_result["passed"]),
        "details": node_result,
    }


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        r = check_parity(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), Path(td))
        print(json.dumps(r, indent=2))
        sys.exit(0 if r["passed"] else 1)
