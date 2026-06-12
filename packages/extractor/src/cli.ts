#!/usr/bin/env node
/**
 * CLI de extraccion batch: lee un archivo JSONL donde cada linea es un
 * CanonicalRequest (parcial) con metadatos de dataset (sample_id, label,
 * timestamp), y escribe un CSV con esas 3 columnas + las 72 features
 * canonicas, en el orden de FEATURE_NAMES.
 *
 * Uso:
 *   node dist/cli.js <input.jsonl> <output.csv>
 *
 * Esta es la unica via por la que los datasets de entrenamiento obtienen
 * features (R1): los notebooks Python emiten CanonicalRequest JSONL y
 * delegan el calculo de features a este CLI.
 */
import * as fs from "fs";
import * as readline from "readline";
import { extractFeatures, FEATURE_NAMES, CanonicalRequest } from "./index";

interface DatasetRecord extends Partial<CanonicalRequest> {
  sample_id?: string | number;
  label?: string | number;
  timestamp?: string;
  _source?: string;
  _row_hash?: string;
}

const FLUSH_EVERY = 1000;

function csvEscape(value: string | number): string {
  const s = String(value);
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

async function main(): Promise<void> {
  const [, , inputPath, outputPath] = process.argv;
  if (!inputPath || !outputPath) {
    console.error("Uso: extractor <input.jsonl> <output.csv>");
    process.exit(1);
  }

  const rl = readline.createInterface({
    input: fs.createReadStream(inputPath, { encoding: "utf-8" }),
    crlfDelay: Infinity,
  });

  const fd = fs.openSync(outputPath, "w");
  const header = ["sample_id", "label", "timestamp", "_source", "_row_hash", ...FEATURE_NAMES];
  fs.writeSync(fd, header.map(csvEscape).join(",") + "\n");

  let buffer = "";
  let bufferedRows = 0;
  let written = 0;
  let skipped = 0;
  let lineNumber = 0;

  const flush = (): void => {
    if (buffer.length > 0) {
      fs.writeSync(fd, buffer);
      buffer = "";
      bufferedRows = 0;
    }
  };

  for await (const line of rl) {
    lineNumber++;
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    let record: DatasetRecord;
    try {
      record = JSON.parse(trimmed);
    } catch {
      console.error(`linea ${lineNumber}: JSON invalido, se omite`);
      skipped++;
      continue;
    }

    const features = extractFeatures(record);
    const row = [
      record.sample_id ?? "",
      record.label ?? "",
      record.timestamp ?? "",
      record._source ?? "",
      record._row_hash ?? "",
      ...FEATURE_NAMES.map((name) => features[name]),
    ];
    buffer += row.map(csvEscape).join(",") + "\n";
    bufferedRows++;
    written++;

    if (bufferedRows >= FLUSH_EVERY) flush();
  }

  flush();
  fs.closeSync(fd);

  console.error(`OK: ${written} filas escritas en ${outputPath} (${skipped} omitidas)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
