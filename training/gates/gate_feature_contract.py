"""
Fase 6, gate 0 — feature-contract gate. Runs first, before any accuracy
metric is evaluated, because a wrong-shaped model can still produce
plausible-looking numbers on the wrong input space (see the Fase 5 finding:
notebooks silently trained/exported IF on 67 features for three retrain
cycles while production if.onnx expected 61 — nothing caught it
automatically).

Deliberately reads the expected dimensions from training/models/parity_report.json
(committed, describes the CURRENT production contract) rather than from the
training notebook — the notebook is exactly what drifted last time, so it
cannot be the source of truth for what the contract should be.
"""
import json
from pathlib import Path

import onnxruntime as ort

REPO = Path(__file__).parent.parent.parent
PARITY_REPORT_PATH = REPO / "training" / "models" / "parity_report.json"


def check_feature_contract(candidate_rf_path, candidate_if_path, parity_report_path: Path = PARITY_REPORT_PATH) -> dict:
    """Verifies candidate ONNX models accept exactly the same input
    dimensions as production worker.ts expects."""
    expected = json.loads(Path(parity_report_path).read_text())

    rf_session = ort.InferenceSession(str(candidate_rf_path))
    if_session = ort.InferenceSession(str(candidate_if_path))

    rf_actual_dims = rf_session.get_inputs()[0].shape[1]
    if_actual_dims = if_session.get_inputs()[0].shape[1]

    rf_pass = rf_actual_dims == expected["rf_n_features"]
    if_pass = if_actual_dims == expected["if_n_features"]

    return {
        "gate": "feature_contract",
        "passed": bool(rf_pass and if_pass),
        "details": {
            "rf_expected": expected["rf_n_features"],
            "rf_actual": rf_actual_dims,
            "if_expected": expected["if_n_features"],
            "if_actual": if_actual_dims,
        },
    }
