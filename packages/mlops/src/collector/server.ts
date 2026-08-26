/**
 * MLOps telemetry collector (Fase 1 of the CT/CI/CD pipeline).
 *
 * Exposes POST /telemetry, accepting the feature vectors that logsguardian's
 * middleware sends fire-and-forget (see packages/core/src/telemetry.ts) when
 * `telemetryUrl` is configured. Never receives raw request payloads — only
 * the 73-feature vector plus predicted_class/confidence/timestamp/source_id.
 */
import express, { type Express } from "express";
import { validateTelemetryPayload } from "./schema";
import { TelemetryStore } from "./store";

const JSON_BODY_LIMIT = "64kb";

export interface CollectorOptions {
  dbPath?: string;
}

export interface Collector {
  app: Express;
  store: TelemetryStore;
}

export function createCollectorApp(options: CollectorOptions = {}): Collector {
  const store = new TelemetryStore(options.dbPath);
  const app = express();
  app.use(express.json({ limit: JSON_BODY_LIMIT }));

  app.post("/telemetry", (req, res) => {
    const result = validateTelemetryPayload(req.body);
    if (!result.valid) {
      res.status(400).json({ error: result.error });
      return;
    }
    const id = store.add(result.payload);
    res.status(201).json({ id });
  });

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok", events: store.count(), sources: store.sources().length });
  });

  return { app, store };
}
