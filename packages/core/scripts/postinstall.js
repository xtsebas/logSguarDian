#!/usr/bin/env node
"use strict";

/**
 * Prints a one-time welcome message after `npm install logsguardian`.
 *
 * Deliberately static — no prompts, no stdin, no network. A postinstall
 * script that waits on interactive input hangs forever in any non-TTY
 * context (CI, `docker build`, an automated deploy), which is exactly
 * where this package is most likely to be installed. Configuration itself
 * still happens explicitly via `logsguardian config init`, not here.
 *
 * Wrapped so this can never fail someone's `npm install` — a welcome
 * banner is not worth breaking an install over.
 *
 * BANNER below is copied verbatim, character-for-character, from the
 * source ASCII art — do not hand-retype or "fix" the alignment.
 */

const BANNER =
  "██░░░░░▄█████▄░▄██████░▄██████░▄██████░██░░░██░▄████▄░█████▄░██████▄░██████░▄████▄░██████▄\n" +
  "██░░░░░██░░░██░██░░░░░░██░░░░░░██░░░░░░██░░░██░██░░██░██░░██░██░░░██░░░██░░░██░░██░██░░░██\n" +
  "██░░░░░██░░░██░██░░███░▀█████▄░██░░███░██░░░██░██░░██░█████▀░██░░░██░░░██░░░██░░██░██░░░██\n" +
  "██░░░░░██░░░██░██░░░██░░░░░░██░██░░░██░██░░░██░██████░██░░██░██░░░██░░░██░░░██████░██░░░██\n" +
  "██████░▀█████▀░▀█████▀░██████▀░▀█████▀░▀█████▀░██░░██░██░░██░██████▀░██████░██░░██░██░░░██\n" +
  "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░";

function main() {
  console.log("");
  console.log(BANNER);
  console.log("");
  console.log("logsguardian — RASP middleware for Node.js/Express");
  console.log("Detects SQL Injection, XSS, Path Traversal, and Command Injection");
  console.log("in real time using a hybrid ML model (Random Forest + Isolation");
  console.log("Forest), no dedicated security team required.");
  console.log("");
  console.log("  -> Run 'npx logsguardian config init' before mounting the middleware.");
  console.log("");
  console.log("Welcome aboard — we hope you enjoy using logsguardian!");
  console.log("");
}

try {
  main();
} catch {
  // A welcome banner must never fail someone's `npm install`.
}
