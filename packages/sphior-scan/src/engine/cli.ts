/**
 * cli.ts — `sphior-scan run <dir>`（GitHub Action の実体・self-host 基盤）
 *
 * ディレクトリを収集 → runScan → SARIF 出力 → `--fail-on` で終了コード。
 * process に直接依存しない `runCli()`（テスト可能）と、薄い bin ラッパを分離。
 */

import { writeFileSync } from "node:fs";
import type { Severity } from "./types";
import { runScan, type RunScanResult } from "./run";
import { collectSourceFiles } from "./collect";
import { canonicalJson } from "./canonical";
import { buildFixContexts } from "./mcp/fix-context";

const SEV_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface CliContext {
  cwd?: string;
  writeFile?: (path: string, data: string) => void;
  log?: (msg: string) => void;
}

export interface CliResult {
  exitCode: number;
  result?: RunScanResult;
  sarifJson?: string;
  error?: string;
}

function parseFlags(rest: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const val = rest[i + 1] && !rest[i + 1].startsWith("--") ? rest[++i] : "true";
      flags[key] = val;
    }
  }
  return flags;
}

/** テスト可能な CLI 本体。exitCode を返す（process.exit は bin 側）。 */
export function runCli(argv: string[], ctx: CliContext = {}): CliResult {
  const log = ctx.log ?? (() => {});
  const writeFile = ctx.writeFile ?? ((p, d) => writeFileSync(p, d));
  const [cmd, dir, ...rest] = argv;

  if (cmd !== "run" || !dir) {
    log("usage: sphior-scan run <dir> [--sarif out.sarif] [--json out.json] [--fix-context out.json] [--fail-on high]");
    return { exitCode: 2, error: "bad_args" };
  }

  const flags = parseFlags(rest);
  const files = collectSourceFiles(dir);
  const result = runScan({ files });
  const sarifJson = canonicalJson(result.sarif);

  if (flags.sarif) writeFile(flags.sarif, sarifJson);
  if (flags.json) writeFile(flags.json, canonicalJson(result.findings));
  // §0.6: 自前 AI を使わず、決定論 fix-context を出力 → 顧客の AI が MCP/ファイル経由で消費し修正。
  if (flags["fix-context"]) writeFile(flags["fix-context"], canonicalJson(buildFixContexts(result.findings)));
  if (!flags.sarif && !flags.json && !flags["fix-context"]) log(sarifJson);

  const counts = result.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  log(
    `SPHIOR CODE: ${result.findings.length} findings ` +
      `(critical=${counts.critical ?? 0} high=${counts.high ?? 0} medium=${counts.medium ?? 0} low=${counts.low ?? 0}) ` +
      `engine=${result.engine_version} ruleset=${result.ruleset_version}`,
  );

  let exitCode = 0;
  const failOn = flags["fail-on"] as Severity | undefined;
  if (failOn && SEV_ORDER[failOn] !== undefined) {
    const threshold = SEV_ORDER[failOn];
    if (result.findings.some((f) => SEV_ORDER[f.severity] >= threshold)) exitCode = 1;
  }
  return { exitCode, result, sarifJson };
}
