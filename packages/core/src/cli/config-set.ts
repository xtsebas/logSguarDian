import * as fs from "fs";
import { requireConfig, resolveConfigPath } from "./guard";

type SupportedKey = "threshold" | "mode" | "model" | "telemetry";

const VALIDATORS: Record<SupportedKey, (raw: string) => unknown> = {
  threshold: (raw) => {
    const n = parseFloat(raw);
    if (isNaN(n) || n < 0 || n > 1) {
      throw new Error(`threshold must be a number in [0, 1], got '${raw}'`);
    }
    return n;
  },
  mode: (raw) => {
    // 'log' is an input-only alias for 'monitor'
    // mode (block|log), but 'monitor' is the term used everywhere else in
    // the codebase (types.ts, decision-policy.md, config templates, tests).
    // Accepting the alias here means the persisted config always says
    // 'monitor', never 'log' — no second value circulates through the rest
    // of the system.
    if (raw === "log") return "monitor";
    if (raw !== "block" && raw !== "monitor") {
      throw new Error(`mode must be 'block', 'monitor', or 'log', got '${raw}'`);
    }
    return raw;
  },
  model: (raw) => {
    if (raw !== "rf" && raw !== "if" && raw !== "hybrid") {
      throw new Error(`model must be 'rf', 'if', or 'hybrid', got '${raw}'`);
    }
    return raw;
  },
  telemetry: (raw) => {
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      throw new Error(`telemetry must be a valid URL, got '${raw}'`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error(`telemetry URL must be http or https, got '${parsed.protocol.replace(":", "")}'`);
    }
    return raw;
  },
};

/** CLI key -> MiddlewareOptions field, for the rare cases where they differ. */
const CONFIG_FIELD: Record<SupportedKey, string> = {
  threshold: "threshold",
  mode: "mode",
  model: "model",
  telemetry: "telemetryUrl",
};

const SUPPORTED_KEYS = Object.keys(VALIDATORS) as SupportedKey[];

function serializeConfig(opts: Record<string, unknown>): string {
  const lines = [
    "// logsguardian.config.js — managed by logsguardian CLI",
    "/** @type {import('logsguardian').MiddlewareOptions} */",
    "module.exports = {",
  ];
  for (const [key, value] of Object.entries(opts)) {
    const serialized = typeof value === "string" ? `'${value}'` : String(value);
    lines.push(`  ${key}: ${serialized},`);
  }
  lines.push("};");
  return lines.join("\n") + "\n";
}

export function runConfigSet(args: string[]): void {
  const [key, rawValue] = args;

  if (!key || rawValue === undefined) {
    console.error("logsguardian: config set requires a key and a value");
    console.error("Usage: logsguardian config set <key> <value>");
    console.error(`Supported keys: ${SUPPORTED_KEYS.join(", ")}`);
    process.exit(1);
  }

  if (!SUPPORTED_KEYS.includes(key as SupportedKey)) {
    console.error(`logsguardian: unknown config key '${key}'`);
    console.error(`Supported keys: ${SUPPORTED_KEYS.join(", ")}`);
    process.exit(1);
  }

  let parsed: unknown;
  try {
    parsed = VALIDATORS[key as SupportedKey](rawValue);
  } catch (err) {
    console.error(`logsguardian: invalid value — ${(err as Error).message}`);
    process.exit(1);
  }

  // Load the current config, apply the change, rewrite.
  const current = requireConfig() as unknown as Record<string, unknown>;
  const field = CONFIG_FIELD[key as SupportedKey];
  const updated: Record<string, unknown> = { ...current, [field]: parsed };

  fs.writeFileSync(resolveConfigPath(), serializeConfig(updated), "utf-8");
  console.log(`Set ${key} = ${JSON.stringify(parsed)}`);
}
