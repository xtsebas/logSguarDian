/**
 * Fire-and-forget telemetry dispatcher for the MLOps collector (CT pipeline).
 *
 * Sends a single HTTP(S) POST with a TelemetryEvent (feature vector only,
 * never the raw request payload) as JSON body. Mirrors webhook.ts: any error
 * (unreachable host, timeout, malformed URL) is swallowed silently — telemetry
 * failures must never affect the host application. Kept as a separate module
 * from webhook.ts because it's a distinct concern (MLOps data collection vs.
 * alerting) with its own payload shape, following the same split already
 * used for store.ts/webhook-store.ts.
 */
import * as http from "http";
import * as https from "https";
import type { TelemetryEvent } from "./types";

export function sendTelemetry(url: string, event: TelemetryEvent): Promise<number | null> {
  return new Promise((resolve) => {
    try {
      const body = JSON.stringify(event);
      const parsed = new URL(url);
      const transport = parsed.protocol === "https:" ? https : http;
      const options: http.RequestOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "User-Agent": "logsguardian/0.1.0",
        },
      };

      const req = transport.request(options, (res) => {
        res.resume(); // drain body — we don't read the response
        resolve(res.statusCode ?? null);
      });

      req.on("error", () => resolve(null)); // silent fail
      req.setTimeout(3000, () => {
        req.destroy();
        resolve(null);
      });
      req.write(body);
      req.end();
    } catch {
      // malformed URL or any synchronous error — silent fail
      resolve(null);
    }
  });
}
