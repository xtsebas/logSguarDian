"""
Generate parity fixture for packages/core/tests/parity.node.test.ts (F4.3).

val.parquet is gitignored, so synthetic float32 inputs are used instead.
This is valid for a runtime-parity test: we verify that onnxruntime-node
produces the same numbers as onnxruntime (Python) on identical inputs.
The Python sklearn->Python onnxruntime parity was already verified in
05_onnx_export.ipynb (max_prob_diff=1.6e-7, max_score_diff=1.9e-7).

Outputs:
  packages/core/tests/fixtures/parity_fixture.json
  {
    "inputs":       [[...66 float32s...], ...100 rows],
    "rf_expected":  [[5 probs],           ...100 rows],
    "if_expected":  [score,               ...100 values]
  }

EXCLUDED_FEATURE_INDICES (0-based): [66, 67, 68, 69, 70, 71]
  = status_code, req_count_1s, req_count_5s, req_count_60s,
    error_rate_4xx_60s, endpoint_diversity_60s
Model input: 66 features (indices 0-65 of the 72-feature vector).
"""

import json
import os
from pathlib import Path

import numpy as np
import onnxruntime as ort

REPO = Path(__file__).parent.parent
MODEL_DIR = REPO / "training" / "models"
FIXTURE_PATH = REPO / "packages" / "core" / "tests" / "fixtures" / "parity_fixture.json"
FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)

N_SAMPLES = 100
N_FEATURES = 66
RANDOM_STATE = 42

PARITY_REPORT = json.loads((MODEL_DIR / "parity_report.json").read_text())
assert PARITY_REPORT["n_features"] == N_FEATURES, (
    f"parity_report.json n_features={PARITY_REPORT['n_features']}, expected {N_FEATURES}"
)
assert PARITY_REPORT["parity_passed"] is True, "parity_report.json: parity_passed must be true"

RF_OUTPUT_IDX = PARITY_REPORT["rf_onnx_output_index"]
IF_OUTPUT_IDX = PARITY_REPORT["if_onnx_output_index"]

rng = np.random.RandomState(RANDOM_STATE)
inputs = rng.rand(N_SAMPLES, N_FEATURES).astype(np.float32)

rf_sess = ort.InferenceSession(str(MODEL_DIR / "rf.onnx"))
if_sess = ort.InferenceSession(str(MODEL_DIR / "if.onnx"))

rf_expected = []
if_expected = []

for i in range(N_SAMPLES):
    row = inputs[i : i + 1]
    rf_out = rf_sess.run(None, {"float_input": row})
    if_out = if_sess.run(None, {"float_input": row})

    probs = rf_out[RF_OUTPUT_IDX][0].tolist()
    score = float(if_out[IF_OUTPUT_IDX][0][0])

    rf_expected.append(probs)
    if_expected.append(score)

fixture = {
    "inputs": inputs.tolist(),
    "rf_expected": rf_expected,
    "if_expected": if_expected,
}

FIXTURE_PATH.write_text(json.dumps(fixture, indent=2))

print(f"Fixture written: {FIXTURE_PATH}")
print(f"  inputs shape : ({N_SAMPLES}, {N_FEATURES})")
print(f"  rf_expected  : {N_SAMPLES} rows × {len(rf_expected[0])} classes")
print(f"  if_expected  : {N_SAMPLES} scores")
print(f"  RF output index used : {RF_OUTPUT_IDX} ({rf_sess.get_outputs()[RF_OUTPUT_IDX].name})")
print(f"  IF output index used : {IF_OUTPUT_IDX} ({if_sess.get_outputs()[IF_OUTPUT_IDX].name})")
print(f"  RF classes : {PARITY_REPORT['rf_classes']}")
print(f"  Sample RF probs[0] : {rf_expected[0]}")
print(f"  Sample IF score[0] : {if_expected[0]:.8f}")
