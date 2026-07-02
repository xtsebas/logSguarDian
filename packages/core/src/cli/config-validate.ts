import * as fs from "fs";
import * as path from "path";
import { requireConfig } from "./guard";
import type { MiddlewareOptions } from "../types";

export function runConfigValidate(): void {
  const config = requireConfig() as unknown as MiddlewareOptions;
  const errors: string[] = [];

  // mode
  if (config.mode !== undefined) {
    if (config.mode !== "block" && config.mode !== "monitor") {
      errors.push(`mode: must be 'block' or 'monitor', got '${config.mode}'`);
    }
  }

  // threshold
  if (config.threshold !== undefined) {
    const t = config.threshold;
    if (typeof t !== "number" || isNaN(t) || t < 0 || t > 1) {
      errors.push(`threshold: must be a number in [0, 1], got ${JSON.stringify(t)}`);
    }
  }

  // model selection
  if (config.model !== undefined) {
    if (config.model !== "rf" && config.model !== "if" && config.model !== "hybrid") {
      errors.push(`model: must be 'rf', 'if', or 'hybrid', got '${config.model}'`);
    }
  }

  // timeoutMs
  if (config.timeoutMs !== undefined) {
    if (typeof config.timeoutMs !== "number" || config.timeoutMs <= 0 || !Number.isInteger(config.timeoutMs)) {
      errors.push(`timeoutMs: must be a positive integer, got ${JSON.stringify(config.timeoutMs)}`);
    }
  }

  // dbPath
  if (config.dbPath !== undefined) {
    if (typeof config.dbPath !== "string" || config.dbPath.trim() === "") {
      errors.push(`dbPath: must be a non-empty string, got ${JSON.stringify(config.dbPath)}`);
    }
  }

  // modelDir and model file existence
  if (config.modelDir !== undefined) {
    const modelDir = config.modelDir;
    if (!fs.existsSync(modelDir)) {
      errors.push(`modelDir: directory does not exist: '${modelDir}'`);
    } else {
      const selection = config.model ?? "hybrid";
      const needsRf = selection === "rf" || selection === "hybrid";
      const needsIf = selection === "if" || selection === "hybrid";

      if (needsRf && !fs.existsSync(path.join(modelDir, "rf.onnx"))) {
        errors.push(`modelDir: 'rf.onnx' not found in '${modelDir}'`);
      }
      if (needsIf && !fs.existsSync(path.join(modelDir, "if.onnx"))) {
        errors.push(`modelDir: 'if.onnx' not found in '${modelDir}'`);
      }
    }
  }

  if (errors.length > 0) {
    console.error("logsguardian: configuration has errors:\n");
    for (const e of errors) {
      console.error(`  - ${e}`);
    }
    console.error();
    process.exit(1);
  }

  console.log("Configuration is valid.");
}
