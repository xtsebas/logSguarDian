"""
Unit tests for the Fase 6 gate functions — fast, no real training run or
ONNX model needed (that level of verification is the manual sabotage-and-
revert check described in the Fase 6 commit / task notes, run against real
candidates). These test each gate's own pass/fail logic in isolation via
mocks and synthetic metadata.

Uses the standard library's unittest rather than pytest — pytest isn't a
project dependency (training/requirements.txt doesn't list it) and this
project's Python side has no other test suite to match conventions against,
so unittest avoids adding a new unpinned dependency for one test file.

Run: python3 -m unittest training/gates/test_gates.py -v
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent))

from gate_feature_contract import check_feature_contract
from gate_metrics import check_metrics
from gate_memory import TOTAL_DELTA_RE, RSS_GATE_MB


class TestFeatureContractGate(unittest.TestCase):
    def _fake_session(self, dims: int) -> MagicMock:
        session = MagicMock()
        input_mock = MagicMock()
        input_mock.shape = [None, dims]
        session.get_inputs.return_value = [input_mock]
        return session

    def test_passes_when_dims_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "parity_report.json"
            report_path.write_text(json.dumps({"rf_n_features": 67, "if_n_features": 61}))

            with patch("gate_feature_contract.ort.InferenceSession") as mock_session:
                mock_session.side_effect = [self._fake_session(67), self._fake_session(61)]
                result = check_feature_contract("rf.onnx", "if.onnx", parity_report_path=report_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["details"]["rf_actual"], 67)
        self.assertEqual(result["details"]["if_actual"], 61)

    def test_fails_when_if_dims_drift_reproducing_fase5_bug(self):
        """The exact class of bug found in Fase 5: IF trained on 67 features
        instead of the production-contract 61."""
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "parity_report.json"
            report_path.write_text(json.dumps({"rf_n_features": 67, "if_n_features": 61}))

            with patch("gate_feature_contract.ort.InferenceSession") as mock_session:
                mock_session.side_effect = [self._fake_session(67), self._fake_session(67)]
                result = check_feature_contract("rf.onnx", "if.onnx", parity_report_path=report_path)

        self.assertFalse(result["passed"])
        self.assertEqual(result["details"]["if_expected"], 61)
        self.assertEqual(result["details"]["if_actual"], 67)

    def test_fails_when_rf_dims_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "parity_report.json"
            report_path.write_text(json.dumps({"rf_n_features": 67, "if_n_features": 61}))

            with patch("gate_feature_contract.ort.InferenceSession") as mock_session:
                mock_session.side_effect = [self._fake_session(73), self._fake_session(61)]
                result = check_feature_contract("rf.onnx", "if.onnx", parity_report_path=report_path)

        self.assertFalse(result["passed"])


class TestMetricsGate(unittest.TestCase):
    def _write_meta(self, tmp: str, rf: dict, if_: dict) -> tuple[Path, Path]:
        rf_path = Path(tmp) / "rf_meta.json"
        if_path = Path(tmp) / "if_meta.json"
        rf_path.write_text(json.dumps(rf))
        if_path.write_text(json.dumps(if_))
        return rf_path, if_path

    def test_passes_with_3_of_4_classes_and_if_within_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            rf_path, if_path = self._write_meta(
                tmp,
                {"per_class_f1": {"sqli": 0.90, "xss": 0.85, "path_traversal": 0.79, "cmdi": 0.93}},
                {"val_recall": 0.91, "val_fp_rate": 0.05},
            )
            result = check_metrics(rf_path, if_path)

        self.assertTrue(result["passed"])
        self.assertEqual(result["details"]["rf_classes_passing"], 3)

    def test_fails_with_only_2_of_4_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            rf_path, if_path = self._write_meta(
                tmp,
                {"per_class_f1": {"sqli": 0.90, "xss": 0.85, "path_traversal": 0.70, "cmdi": 0.60}},
                {"val_recall": 0.91, "val_fp_rate": 0.05},
            )
            result = check_metrics(rf_path, if_path)

        self.assertFalse(result["passed"])
        self.assertEqual(result["details"]["rf_classes_passing"], 2)

    def test_fails_when_if_fp_exceeds_the_006_target_even_if_recall_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            rf_path, if_path = self._write_meta(
                tmp,
                {"per_class_f1": {"sqli": 0.90, "xss": 0.85, "path_traversal": 0.79, "cmdi": 0.93}},
                {"val_recall": 0.95, "val_fp_rate": 0.08},  # would pass the looser 0.10 ceiling
            )
            result = check_metrics(rf_path, if_path)

        self.assertFalse(result["passed"])
        self.assertFalse(result["details"]["if_passed"])

    def test_fails_when_if_recall_below_050(self):
        with tempfile.TemporaryDirectory() as tmp:
            rf_path, if_path = self._write_meta(
                tmp,
                {"per_class_f1": {"sqli": 0.90, "xss": 0.85, "path_traversal": 0.79, "cmdi": 0.93}},
                {"val_recall": 0.40, "val_fp_rate": 0.02},
            )
            result = check_metrics(rf_path, if_path)

        self.assertFalse(result["passed"])


class TestMemoryGateParsing(unittest.TestCase):
    def test_regex_extracts_total_delta_rss(self):
        sample_output = (
            "=== SUMMARY ===\n"
            "Delta RSS from loading both models:     150.00 MB\n"
            "Total Delta RSS (baseline -> fully warm): 245.32 MB\n"
        )
        match = TOTAL_DELTA_RE.search(sample_output)
        self.assertIsNotNone(match)
        self.assertEqual(float(match.group(1)), 245.32)

    def test_gate_threshold_is_300mb(self):
        self.assertEqual(RSS_GATE_MB, 300.0)


if __name__ == "__main__":
    unittest.main()
