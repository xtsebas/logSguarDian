import * as path from "path";
import * as fs from "fs";
import type { MiddlewareOptions } from "../types";

export const CONFIG_FILENAME = "logsguardian.config.js";

export function resolveConfigPath(): string {
  return path.join(process.cwd(), CONFIG_FILENAME);
}

/**
 * Loads logsguardian.config.js from cwd.
 * Exits with a clear error if the file is missing — enforces the rule that
 * all commands other than `config init` require an initialised project.
 */
export function requireConfig(): MiddlewareOptions {
  const configPath = resolveConfigPath();
  if (!fs.existsSync(configPath)) {
    console.error(
      `logsguardian: no config found in ${process.cwd()}\n` +
        `Run 'logsguardian config init' to initialise the project.`
    );
    process.exit(1);
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require(configPath) as MiddlewareOptions;
  } catch (err) {
    console.error(`logsguardian: failed to load ${CONFIG_FILENAME}: ${String(err)}`);
    process.exit(1);
  }
}

/**
 * Parses `--format <value>` from CLI args, validating it against the given
 * allowed values. Exits with a clear error on an unrecognized value instead
 * of silently falling back to the default — a typo (`--format jsno`) must
 * not produce silently-wrong output with no indication anything was
 * misspelled.
 */
export function parseFormat<T extends string>(args: string[], valid: readonly T[], defaultFormat: T): T {
  const idx = args.indexOf("--format");
  if (idx === -1) return defaultFormat;
  const raw = args[idx + 1];
  if (!(valid as readonly string[]).includes(raw)) {
    console.error(`logsguardian: --format must be ${valid.map((v) => `'${v}'`).join(" or ")}, got '${raw}'`);
    process.exit(1);
  }
  return raw as T;
}

/**
 * Printed under an unexpectedly-empty report (a DB file that exists, opens,
 * and returns zero rows) — as opposed to the "no database found" error above,
 * which fires when the file doesn't exist at all.
 *
 * requireConfig() loads `dbPath` from logsguardian.config.js, but the
 * middleware's own EventStore/WebhookStore open whatever `dbPath` the host
 * app actually passes to `logsguardian(options)` at runtime — two separate
 * Node processes, each with its own view of "the config", and nothing
 * connects them. If the host app doesn't literally
 * `require('./logsguardian.config.js')` and pass it straight through (e.g.
 * it hardcodes options inline, or merges in its own dbPath), the CLI silently
 * ends up reading a different, valid, empty SQLite file — same schema, zero
 * rows, no error anywhere. Found the hard way once already (see
 * .claude/decisiones.md) — this hint exists so the next person doesn't have
 * to re-diagnose it from scratch.
 */
export function dbPathMismatchHint(dbPath: string): string {
  return (
    `  (If you expected results here: this file exists and opened fine at\n` +
    `   '${dbPath}', it's just empty. Double-check that 'dbPath' in\n` +
    `   logsguardian.config.js matches whatever your app actually passes to\n` +
    `   logsguardian(options) at runtime — they're independent unless your\n` +
    `   app does app.use(logsguardian(require('./logsguardian.config.js'))).\n` +
    `   A mismatch here never errors; the CLI just reads a different, valid,\n` +
    `   empty database than the one your app is writing to.)\n`
  );
}
