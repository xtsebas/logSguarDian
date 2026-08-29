#!/usr/bin/env node
/**
 * Node-side half of the Fase 6 parity gate (training/gates/gate_parity.py).
 *
 * Standalone equivalent of packages/core/tests/parity.node.test.ts's two
 * comparison tests, parameterized over an arbitrary candidate model
 * dir + fixture path instead of the hardcoded production paths — the
 * production test itself is untouched. Same tolerance (1e-5), same
 * output-index convention (index 1 for both RF probs and IF score).
 *
 * Usage:
 *   node parity_check_node.js <rf_onnx_path> <if_onnx_path> <fixture_json_path>
 *
 * Exit 0 and prints a JSON result line if both max diffs are within
 * tolerance; exit 1 otherwise.
 */
const fs = require("fs");
const path = require("path");
const ort = require(
  path.join(__dirname, "../../node_modules/.pnpm/onnxruntime-node@1.26.0/node_modules/onnxruntime-node")
);

const TOLERANCE = 1e-5;
const RF_OUTPUT_IDX = 1;
const IF_OUTPUT_IDX = 1;

async function main() {
  const [, , rfPath, ifPath, fixturePath] = process.argv;
  if (!rfPath || !ifPath || !fixturePath) {
    console.error("Usage: parity_check_node.js <rf_onnx_path> <if_onnx_path> <fixture_json_path>");
    process.exit(1);
  }

  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf-8"));
  const rfSession = await ort.InferenceSession.create(rfPath);
  const ifSession = await ort.InferenceSession.create(ifPath);

  let rfMaxDiff = 0;
  const rfOutputName = rfSession.outputNames[RF_OUTPUT_IDX];
  for (let i = 0; i < fixture.rf_inputs.length; i++) {
    const input = new ort.Tensor("float32", Float32Array.from(fixture.rf_inputs[i]), [1, fixture.rf_inputs[i].length]);
    const result = await rfSession.run({ float_input: input });
    const probs = result[rfOutputName].data;
    for (let c = 0; c < probs.length; c++) {
      rfMaxDiff = Math.max(rfMaxDiff, Math.abs(probs[c] - fixture.rf_expected[i][c]));
    }
  }

  let ifMaxDiff = 0;
  const ifOutputName = ifSession.outputNames[IF_OUTPUT_IDX];
  for (let i = 0; i < fixture.if_inputs.length; i++) {
    const input = new ort.Tensor("float32", Float32Array.from(fixture.if_inputs[i]), [1, fixture.if_inputs[i].length]);
    const result = await ifSession.run({ float_input: input });
    const score = result[ifOutputName].data[0];
    ifMaxDiff = Math.max(ifMaxDiff, Math.abs(score - fixture.if_expected[i]));
  }

  const passed = rfMaxDiff < TOLERANCE && ifMaxDiff < TOLERANCE;
  console.log(JSON.stringify({ rf_max_diff: rfMaxDiff, if_max_diff: ifMaxDiff, tolerance: TOLERANCE, passed }));
  process.exit(passed ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
