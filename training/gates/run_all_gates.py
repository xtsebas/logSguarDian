#!/usr/bin/env python3
"""
Fase 6 — runs all CT pipeline candidate gates in sequence, fail-fast.

Gate order is deliberate: cheapest and most likely to catch the exact class
of bug found in Fase 5 (feature-contract drift) runs first, before spending
time on the expensive E2E/memory gates against a model that might have the
wrong input shape entirely.

Usage:
    python3 training/gates/run_all_gates.py [--candidate-dir DIR]

Exit 0 if APPROVED_FOR_CANARY, exit 1 if REJECTED (or any gate itself
errors) — this is deliberately unlike run_notebooks.py's original bug
(silent exit 0 on failure, fixed in Fase 5): the whole point of a gate is
that a non-zero exit here must actually mean "do not deploy this."
"""
import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gate_feature_contract import check_feature_contract  # noqa: E402
from gate_metrics import check_metrics  # noqa: E402
from gate_parity import check_parity  # noqa: E402
from gate_e2e import check_e2e  # noqa: E402
from gate_memory import check_memory  # noqa: E402

REPO = Path(__file__).parent.parent.parent
DEFAULT_CANDIDATE_DIR = REPO / "training" / "models"
REPORT_DIR = REPO / "training" / "results"


def log(msg: str) -> None:
    print(f"[gates] {msg}")


def write_gate_report(results: list[dict], status: str) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"gate_report_{ts}.json"
    report = {
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gates": results,
    }
    report_path.write_text(json.dumps(report, indent=2))
    return report_path


def run_all_gates(candidate_dir: Path) -> bool:
    candidate_dir = Path(candidate_dir)
    rf_onnx = candidate_dir / "rf_candidate.onnx"
    if_onnx = candidate_dir / "if_candidate.onnx"
    rf_meta = candidate_dir / "rf_candidate_metadata.json"
    if_meta = candidate_dir / "if_candidate_metadata.json"

    for path in (rf_onnx, if_onnx, rf_meta, if_meta):
        if not path.exists():
            log(f"FATAL: expected candidate artifact not found: {path}")
            write_gate_report(
                [{"gate": "setup", "passed": False, "details": {"missing_file": str(path)}}],
                status="REJECTED",
            )
            return False

    results: list[dict] = []

    log("Running gate 0/4: feature_contract")
    contract_result = check_feature_contract(rf_onnx, if_onnx)
    results.append(contract_result)
    if not contract_result["passed"]:
        log("GATE FAILED: feature_contract")
        log(json.dumps(contract_result["details"], indent=2))
        report_path = write_gate_report(results, status="REJECTED")
        log(f"Report: {report_path}")
        return False

    log("Running gate 1/4: metrics")
    metrics_result = check_metrics(rf_meta, if_meta)
    results.append(metrics_result)
    if not metrics_result["passed"]:
        log("GATE FAILED: metrics")
        log(json.dumps(metrics_result["details"], indent=2))
        report_path = write_gate_report(results, status="REJECTED")
        log(f"Report: {report_path}")
        return False

    log("Running gate 2/4: parity")
    with tempfile.TemporaryDirectory(prefix="lg-parity-gate-") as tmp:
        parity_result = check_parity(
            rf_onnx, if_onnx,
            contract_result["details"]["rf_actual"],
            contract_result["details"]["if_actual"],
            Path(tmp),
        )
    results.append(parity_result)
    if not parity_result["passed"]:
        log("GATE FAILED: parity")
        log(json.dumps(parity_result["details"], indent=2))
        report_path = write_gate_report(results, status="REJECTED")
        log(f"Report: {report_path}")
        return False

    log("Running gate 3/4: e2e (this one's slow — real inference over the e2e corpus)")
    e2e_result = check_e2e(rf_onnx, if_onnx)
    results.append(e2e_result)
    if not e2e_result["passed"]:
        log("GATE FAILED: e2e")
        log(e2e_result["details"]["stdout_tail"])
        log(e2e_result["details"]["stderr_tail"])
        report_path = write_gate_report(results, status="REJECTED")
        log(f"Report: {report_path}")
        return False

    log("Running gate 4/4: memory")
    memory_result = check_memory(rf_onnx, if_onnx)
    results.append(memory_result)
    if not memory_result["passed"]:
        log("GATE FAILED: memory")
        log(json.dumps(memory_result["details"], indent=2))
        report_path = write_gate_report(results, status="REJECTED")
        log(f"Report: {report_path}")
        return False

    report_path = write_gate_report(results, status="APPROVED_FOR_CANARY")
    log(f"ALL GATES PASSED — APPROVED_FOR_CANARY. Report: {report_path}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, default=DEFAULT_CANDIDATE_DIR)
    args = parser.parse_args()

    approved = run_all_gates(args.candidate_dir)
    sys.exit(0 if approved else 1)


if __name__ == "__main__":
    main()
