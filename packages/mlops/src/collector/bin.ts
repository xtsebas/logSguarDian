#!/usr/bin/env node
import { createCollectorApp } from "./server";

const DEFAULT_PORT = 4790;
const port = Number(process.env.MLOPS_COLLECTOR_PORT ?? DEFAULT_PORT);
const dbPath = process.env.MLOPS_COLLECTOR_DB;

const { app, store } = createCollectorApp({ dbPath });

const server = app.listen(port, () => {
  console.log(`mlops telemetry collector listening on :${port}`);
});

function shutdown(): void {
  server.close(() => {
    store.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
