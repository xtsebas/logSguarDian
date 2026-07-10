/**
 * Fire-and-forget webhook dispatcher (A16/A23).
 *
 * Sends a single HTTP(S) POST with the DetectionEvent as JSON body.
 * Any error (unreachable host, timeout, malformed URL) is swallowed silently —
 * webhook failures must never affect the host application.
 */
import * as http from "http";
import * as https from "https";
import type { DetectionEvent } from "./types";

export function sendWebhook(url: string, event: DetectionEvent): void {
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
    });

    req.on("error", () => { /* silent fail */ });
    req.setTimeout(3000, () => req.destroy());
    req.write(body);
    req.end();
  } catch {
    // malformed URL or any synchronous error — silent fail
  }
}
