import { requireConfig, parseFormat } from "./guard";

export function runConfigShow(args: string[]): void {
  const config = requireConfig();

  const format = parseFormat(args, ["table", "json"] as const, "table");

  if (format === "json") {
    console.log(JSON.stringify(config, null, 2));
    return;
  }

  const rows = flattenConfig(config as unknown as Record<string, unknown>);
  const keyWidth = Math.max(...rows.map(([k]) => k.length), 3);

  console.log("\nlogSguarDian — Active Configuration\n");
  console.log("  " + "KEY".padEnd(keyWidth + 2) + "VALUE");
  console.log("  " + "─".repeat(keyWidth + 2) + "─".repeat(24));
  for (const [key, value] of rows) {
    console.log("  " + key.padEnd(keyWidth + 2) + String(value));
  }
  console.log();
}

function flattenConfig(
  obj: Record<string, unknown>,
  prefix = ""
): [string, unknown][] {
  const rows: [string, unknown][] = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      rows.push(...flattenConfig(v as Record<string, unknown>, key));
    } else {
      rows.push([key, v]);
    }
  }
  return rows;
}
