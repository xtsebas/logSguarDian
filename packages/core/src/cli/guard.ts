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
