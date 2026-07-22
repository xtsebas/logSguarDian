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
import { runConfigSet } from "./cli/config-set";
import { runConfigValidate } from "./cli/config-validate";
import { runAttacksList } from "./cli/attacks-list";
import { runAttacksSummary } from "./cli/attacks-summary";
import { runAttacksInspect } from "./cli/attacks-inspect";
import { runEndpointsTop } from "./cli/endpoints-top";
import { runEndpointsProfile } from "./cli/endpoints-profile";
import { runEndpointsReport } from "./cli/endpoints-report";
import { runWebhooksAdd } from "./cli/webhooks-add";
import { runWebhooksRemove } from "./cli/webhooks-remove";
import { runWebhooksList } from "./cli/webhooks-list";
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

  case "config set":
    runConfigSet(commandArgs);
    break;

  case "config validate":
    runConfigValidate();
    break;

  case "attacks list":
    runAttacksList(commandArgs);
    break;

  case "attacks summary":
    runAttacksSummary(commandArgs);
    break;

  case "attacks inspect":
    runAttacksInspect(commandArgs);
    break;

  case "endpoints top":
    runEndpointsTop(commandArgs);
    break;

  case "endpoints profile":
    runEndpointsProfile(commandArgs);
    break;

  case "endpoints report":
    runEndpointsReport(commandArgs);
    break;

  case "webhooks add":
    runWebhooksAdd(commandArgs);
    break;

  case "webhooks remove":
    runWebhooksRemove(commandArgs);
    break;

  case "webhooks list":
    runWebhooksList(commandArgs);
    break;

  case "":
  case "--help":
  case "-h":
    console.log("Usage: logsguardian <command>\n");
    console.log("Commands:");
    console.log("  config init              Generate logsguardian.config.js with default values");
    console.log("  config show              Print the active configuration");
    console.log("  config set <key> <value> Modify a config key (threshold, mode, model)");
    console.log("  config validate          Check configuration coherence and model file existence");
    console.log("  attacks list             List attack types classified, with counts and last seen");
    console.log("  attacks summary          Attack type distribution by endpoint, period, and severity");
    console.log("  attacks inspect <type>   Detection rate, top features, and payload examples for one type");
    console.log("  endpoints top            Rank routes by detected attack frequency and risk score");
    console.log("  endpoints profile <route> Detailed profile of one route: attack types, hourly");
    console.log("                           distribution, and source IPs/ranges");
    console.log("  endpoints report         Export the full endpoint analysis as JSON or CSV");
    console.log("  webhooks add <url>       Register a webhook destination (HTTPS only)");
    console.log("  webhooks remove <id>     Remove a webhook by ID");
    console.log("  webhooks list            List registered webhooks");
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
