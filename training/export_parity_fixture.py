"""
Generate parity fixture for packages/core/tests/parity.node.test.ts (F4.3).

val.parquet is gitignored, so synthetic float32 inputs are used instead.
This is valid for a runtime-parity test: we verify that onnxruntime-node
produces the same numbers as onnxruntime (Python) on identical inputs.
The Python sklearn->Python onnxruntime parity was already verified in
05_onnx_export.ipynb.

v8: RF and IF no longer share one input vector (see worker.ts) — RF takes
67 features, IF takes 61 (RF's 67 minus 6 further features dropped for
IsolationForest variance stabilization). Each model gets its own
independently-sized synthetic input array.

Outputs:
  packages/core/tests/fixtures/parity_fixture.json
  {
    "rf_inputs":    [[...67 float32s...], ...100 rows],
    "if_inputs":    [[...61 float32s...], ...100 rows],
    "rf_expected":  [[5 probs],           ...100 rows],
    "if_expected":  [score,               ...100 values]
  }
"""

import json
from pathlib import Path

import numpy as np
import onnxruntime as ort

REPO = Path(__file__).parent.parent
MODEL_DIR = REPO / "training" / "models"
FIXTURE_PATH = REPO / "packages" / "core" / "tests" / "fixtures" / "parity_fixture.json"
FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)

N_SAMPLES = 100
RANDOM_STATE = 42

PARITY_REPORT = json.loads((MODEL_DIR / "parity_report.json").read_text())
N_RF_FEATURES = PARITY_REPORT["rf_n_features"]
N_IF_FEATURES = PARITY_REPORT["if_n_features"]
assert PARITY_REPORT["parity_passed"] is True, "parity_report.json: parity_passed must be true"

RF_OUTPUT_IDX = 1
IF_OUTPUT_IDX = 1

rng = np.random.RandomState(RANDOM_STATE)
rf_inputs = rng.rand(N_SAMPLES, N_RF_FEATURES).astype(np.float32)
if_inputs = rng.rand(N_SAMPLES, N_IF_FEATURES).astype(np.float32)

rf_sess = ort.InferenceSession(str(MODEL_DIR / "rf.onnx"))
if_sess = ort.InferenceSession(str(MODEL_DIR / "if.onnx"))

rf_expected = []
if_expected = []

for i in range(N_SAMPLES):
    rf_out = rf_sess.run(None, {"float_input": rf_inputs[i : i + 1]})
    if_out = if_sess.run(None, {"float_input": if_inputs[i : i + 1]})

    probs = rf_out[RF_OUTPUT_IDX][0].tolist()
    score = float(if_out[IF_OUTPUT_IDX][0][0])

    rf_expected.append(probs)
    if_expected.append(score)

fixture = {
    "rf_inputs": rf_inputs.tolist(),
    "if_inputs": if_inputs.tolist(),
    "rf_expected": rf_expected,
    "if_expected": if_expected,
}

FIXTURE_PATH.write_text(json.dumps(fixture, indent=2))

print(f"Fixture written: {FIXTURE_PATH}")
print(f"  rf_inputs shape : ({N_SAMPLES}, {N_RF_FEATURES})")
print(f"  if_inputs shape : ({N_SAMPLES}, {N_IF_FEATURES})")
print(f"  rf_expected  : {N_SAMPLES} rows × {len(rf_expected[0])} classes")
print(f"  if_expected  : {N_SAMPLES} scores")
print(f"  RF classes : {PARITY_REPORT['rf_classes']}")
print(f"  Sample RF probs[0] : {rf_expected[0]}")
print(f"  Sample IF score[0] : {if_expected[0]:.8f}")
