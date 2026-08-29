import path from "path";
import express from "express";
import { logsguardian } from "../packages/core/dist/index.js";

// Overridable so the CT pipeline's Fase 6 E2E gate (training/gates/gate_e2e.py)
// can point this at a temp directory holding a candidate model, without ever
// touching training/models/ (production).
const MODEL_DIR = process.env.LOGSGUARDIAN_E2E_MODEL_DIR
  ?? path.resolve(__dirname, "..", "training", "models");

export function createTestApp() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.use(
    logsguardian({
      mode: "block",
      modelDir: MODEL_DIR,
      timeoutMs: 10000,
      dbPath: ":memory:",
    })
  );

  // Catch-all so every sampled payload (arbitrary paths/methods from the
  // dataset) gets a response instead of a 404, without affecting the 403
  // blocking behaviour applied upstream by the middleware.
  app.all(/.*/, (req, res) => res.json({ status: "ok" }));

  return app;
}
