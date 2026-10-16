/**
 * cli.ts — `sphior-scan run <dir>`（GitHub Action の実体・self-host 基盤）
 *
 * ディレクトリを収集 → runScan → SARIF 出力 → `--fail-on` で終了コード。
 * process に直接依存しない `runCli()`（テスト可能）と、薄い bin ラッパを分離。
 */

import { existsSync, statSync, writeFileSync } from "node:fs";
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
  /**
   * 診断の出力先（stderr 相当）。既定は log。
   * stdout へ SARIF を流す場合、サマリや警告を混ぜると `| jq` が壊れるため分ける。
   */
  logErr?: (msg: string) => void;
  /**
   * stdout が端末か。true なら人が読む形で出し、false（パイプ/リダイレクト）なら
   * 従来どおり SARIF を流す（`sphior-scan run . | jq` を壊さない）。
   * process 非依存を保つため bin 側から渡す。
   */
  isTty?: boolean;
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
  const logErr = ctx.logErr ?? log;
  const writeFile = ctx.writeFile ?? ((p, d) => writeFileSync(p, d));
  const [cmd, dir, ...rest] = argv;

  if (cmd !== "run" || !dir) {
    logErr("usage: sphior-scan run <dir> [--sarif out.sarif] [--json out.json] [--fix-context out.json] [--fail-on high]");
    return { exitCode: 2, error: "bad_args" };
  }

  const flags = parseFlags(rest);

  // 走査対象が存在しないのに「0 findings・exit 0」を返すと、CI のパス打ち間違いが
  // 永久に緑になる。「0 件検出」と「0 件走査」は別物として扱う
  // （証跡側で collection_failure / heartbeat を分けているのと同じ原則）。
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    logErr(`error: directory not found: ${dir}`);
    logErr("  Nothing was scanned, so this is not a clean result. Check the path.");
    return { exitCode: 2, error: "dir_not_found" };
  }

  const files = collectSourceFiles(dir);
  const result = runScan({ files });
  const sarifJson = canonicalJson(result.sarif);

  if (flags.sarif) writeFile(flags.sarif, sarifJson);
  if (flags.json) writeFile(flags.json, canonicalJson(result.findings));
  // §0.6: 自前 AI を使わず、決定論 fix-context を出力 → 顧客の AI が MCP/ファイル経由で消費し修正。
  if (flags["fix-context"]) writeFile(flags["fix-context"], canonicalJson(buildFixContexts(result.findings)));

  // 出力先フラグが無い場合: 端末なら人が読む形、パイプなら SARIF（既存の | jq を維持）。
  if (!flags.sarif && !flags.json && !flags["fix-context"]) {
    if (ctx.isTty) {
      // 表示は重大度の重い順（result.findings 自体は並べ替えない — 正規の順序は
      // kind→location で決まっており、証跡の決定論に関わるため）。
      const rows = [...result.findings]
        .sort((a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity])
        .map((f) => ({
          sev: f.severity,
          loc: `${f.location.path}:${f.location.start_line}`,
          text: `${f.title}${f.cwe ? ` (${f.cwe})` : ""}`,
        }));
      // 桁は実内容から決める（固定幅だと短いパスで間延びする）
      const locW = Math.max(0, ...rows.map((r) => r.loc.length));
      for (const r of rows) logErr(`  ${r.sev.padEnd(8)} ${r.loc.padEnd(locW)}  ${r.text}`);
      if (rows.length > 0) logErr("");
    } else {
      log(sarifJson);
    }
  }

  // 走査対象が 1 件も無いのは「安全」ではなく「見ていない」。黙って 0 件と言わない。
  if (files.length === 0) {
    logErr(`warning: no scannable files found in ${dir} (0 files scanned).`);
  }

  const counts = result.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  logErr(
    `SPHIOR CODE: ${result.findings.length} findings ` +
      `(critical=${counts.critical ?? 0} high=${counts.high ?? 0} medium=${counts.medium ?? 0} low=${counts.low ?? 0}) ` +
      `engine=${result.engine_version} ruleset=${result.ruleset_version}`,
  );

  // 端末実行では「次に何ができるか」を示す（SARIF を読ませるより先に用途を伝える）。
  if (ctx.isTty && !flags.sarif && !flags.json && !flags["fix-context"]) {
    logErr("");
    logErr("  --fix-context fc.json   hand findings to an AI agent to fix");
    logErr("  --sarif out.sarif       for GitHub code scanning / CI dashboards");
    logErr("  --fail-on high          exit 1 if anything at or above this severity (CI)");
  }

  let exitCode = 0;
  const failOn = flags["fail-on"] as Severity | undefined;
  if (failOn && SEV_ORDER[failOn] !== undefined) {
    const threshold = SEV_ORDER[failOn];
    if (result.findings.some((f) => SEV_ORDER[f.severity] >= threshold)) exitCode = 1;
  }
  return { exitCode, result, sarifJson };
}
