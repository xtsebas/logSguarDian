import path from "path";
import express from "express";
import { logsguardian } from "../packages/core/dist/index.js";

const MODEL_DIR = path.resolve(__dirname, "..", "training", "models");

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
