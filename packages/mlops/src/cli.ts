#!/usr/bin/env node
/**
 * mlops CLI entry point (CT/CI/CD pipeline tooling).
 *
 * Usage:
 *   mlops review-clusters   — curate anomaly clusters from Fase 3's report
 */
import { runReviewClusters } from "./cli/review-clusters";

const args = process.argv.slice(2);
const command = args[0] ?? "";
const commandArgs = args.slice(1);

switch (command) {
  case "review-clusters":
    runReviewClusters(commandArgs).catch((err) => {
      console.error(`mlops: review-clusters failed — ${(err as Error).message}`);
      process.exit(1);
    });
    break;

  case "":
  case "--help":
  case "-h":
    console.log("Usage: mlops <command>\n");
    console.log("Commands:");
    console.log("  review-clusters   Curate anomaly clusters from the latest cluster_report_*.json");
    break;

  default:
    console.error(`mlops: unknown command '${args[0]}'`);
    console.error("Run 'mlops --help' to see available commands.");
    process.exit(1);
}
