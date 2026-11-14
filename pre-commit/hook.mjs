#!/usr/bin/env node
// pre-commit hook for SPHIOR CODE.
//
// Runs the scanner (@sphior/scan) on the repository and prints each finding as
// "severity  file:line  title" with its remediation, because pre-commit captures stdout and the
// scanner would otherwise print machine-readable SARIF there. Arguments are passed through
// (e.g. --fail-on high). Exit codes are the scanner's: 0 clean, 1 threshold reached, 2 not scanned.
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const require = createRequire(import.meta.url);
const cli = require.resolve("@sphior/scan/dist/cli.js");
const dir = mkdtempSync(join(tmpdir(), "sphior-code-"));
const out = join(dir, "findings.json");

try {
  const run = spawnSync(process.execPath, [cli, "run", ".", "--json", out, ...process.argv.slice(2)], {
    stdio: ["ignore", "ignore", "inherit"], // the scanner's one-line summary and errors go to stderr
  });
  const code = run.status ?? 2;
  if (code === 2) process.exit(2);

  const order = ["critical", "high", "medium", "low", "info"];
  const findings = JSON.parse(readFileSync(out, "utf8"))
    .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const shown = findings.slice(0, 50);
  for (const f of shown) {
    const where = `${f.location?.path ?? "?"}:${f.location?.start_line ?? "?"}`;
    console.log(`${f.severity.padEnd(8)} ${where}  ${f.title}${f.cwe ? ` [${f.cwe}]` : ""}`);
    if (f.remediation) console.log(`         ${f.remediation}`);
  }
  if (findings.length > shown.length) console.log(`... and ${findings.length - shown.length} more. Run: npx @sphior/scan run .`);
  process.exit(code);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
