import * as ort from "onnxruntime-node";
import * as fs from "fs";
import * as path from "path";

describe("ONNX parity — Node vs Python (F4.3)", () => {
  const FIXTURE_PATH = path.join(__dirname, "fixtures/parity_fixture.json");
  const MODEL_DIR = path.join(__dirname, "../../../training/models");
  const TOLERANCE = 1e-5;

  let fixture: {
    rf_inputs: number[][];
    if_inputs: number[][];
    rf_expected: number[][];
    if_expected: number[];
  };
  let rfSession: ort.InferenceSession;
  let ifSession: ort.InferenceSession;
  let parityReport: {
    parity_passed: boolean;
    rf_n_features: number;
    if_n_features: number;
    rf_onnx_output_index: number;
    if_onnx_output_index: number;
    rf_classes: string[];
    threshold_if: number;
  };

  beforeAll(async () => {
    fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf-8"));
    parityReport = JSON.parse(
      fs.readFileSync(path.join(MODEL_DIR, "parity_report.json"), "utf-8"),
    );
    rfSession = await ort.InferenceSession.create(path.join(MODEL_DIR, "rf.onnx"));
    ifSession = await ort.InferenceSession.create(path.join(MODEL_DIR, "if.onnx"));
  });

  test("parity_report.json reports parity_passed=true, rf_n_features=67, if_n_features=61", () => {
    expect(parityReport.parity_passed).toBe(true);
    expect(parityReport.rf_n_features).toBe(67);
    expect(parityReport.if_n_features).toBe(61);
  });

  test("RF: onnxruntime-node matches Python predict_proba within 1e-5", async () => {
    let maxDiff = 0;
    const outputName = rfSession.outputNames[parityReport.rf_onnx_output_index];

    for (let i = 0; i < fixture.rf_inputs.length; i++) {
      const input = new ort.Tensor(
        "float32",
        Float32Array.from(fixture.rf_inputs[i]),
        [1, parityReport.rf_n_features],
      );
      const result = await rfSession.run({ float_input: input });
      const probs = result[outputName].data as Float32Array;

      for (let c = 0; c < probs.length; c++) {
        const diff = Math.abs(probs[c] - fixture.rf_expected[i][c]);
        maxDiff = Math.max(maxDiff, diff);
      }
    }

    console.log(`RF max diff (Node vs Python): ${maxDiff}`);
    expect(maxDiff).toBeLessThan(TOLERANCE);
  });

  test("IF: onnxruntime-node matches Python decision_function within 1e-5", async () => {
    let maxDiff = 0;
    const outputName = ifSession.outputNames[parityReport.if_onnx_output_index];

    for (let i = 0; i < fixture.if_inputs.length; i++) {
      const input = new ort.Tensor(
        "float32",
        Float32Array.from(fixture.if_inputs[i]),
        [1, parityReport.if_n_features],
      );
      const result = await ifSession.run({ float_input: input });
      const score = (result[outputName].data as Float32Array)[0];

      const diff = Math.abs(score - fixture.if_expected[i]);
      maxDiff = Math.max(maxDiff, diff);
    }

    console.log(`IF max diff (Node vs Python): ${maxDiff}`);
    expect(maxDiff).toBeLessThan(TOLERANCE);
  });

  test("RF class order matches parity_report.rf_classes", () => {
    expect(parityReport.rf_classes).toEqual([
      "benign",
      "cmdi",
      "path_traversal",
      "sqli",
      "xss",
    ]);
  });

  test("IF threshold is consistent with parity_report.threshold_if", () => {
    expect(parityReport.threshold_if).toBeCloseTo(0.00333, 4);
  });
});
