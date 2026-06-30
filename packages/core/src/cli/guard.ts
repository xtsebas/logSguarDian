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
