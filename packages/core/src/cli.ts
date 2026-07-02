#!/usr/bin/env node
/**
 * logsguardian CLI entry point.
 *
 * All commands except `config init` require logsguardian.config.js to exist
 * in the current directory. Running any other command without it exits with
 * a clear error and instructions.
 *
 * Usage:
 *   logsguardian config init   — generate logsguardian.config.js with defaults
 */
import { runConfigInit } from "./cli/config-init";
import { runConfigShow } from "./cli/config-show";
import { requireConfig } from "./cli/guard";

const args = process.argv.slice(2);
const command = args.slice(0, 2).join(" ").trim();
const commandArgs = args.slice(2);

switch (command) {
  case "config init":
    runConfigInit();
    break;

  case "config show":
    runConfigShow(commandArgs);
    break;

  case "":
  case "--help":
  case "-h":
    console.log("Usage: logsguardian <command>\n");
    console.log("Commands:");
    console.log("  config init   Generate logsguardian.config.js with default values");
    console.log("  config show   Print the active configuration");
    console.log("\nAll commands except 'config init' require logsguardian.config.js");
    console.log("in the current directory. Run 'logsguardian config init' first.");
    break;

  default:
    // Guard: any other command requires an initialised config.
    requireConfig();
    console.error(`logsguardian: unknown command '${args[0]}'`);
    console.error("Run 'logsguardian --help' to see available commands.");
    process.exit(1);
}
