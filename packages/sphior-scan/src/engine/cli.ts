/**
 * cli.ts — `sphior-scan run <dir>`（GitHub Action の実体・self-host 基盤）
 *
 * ディレクトリを収集 → runScan → SARIF 出力 → `--fail-on` で終了コード。
 * process に直接依存しない `runCli()`（テスト可能）と、薄い bin ラッパを分離。
 */

import { existsSync, statSync, writeFileSync } from "node:fs";
import type { Severity } from "./types";
import { runScan, type RunScanResult } from "./run";
import { collectSourceFiles, readSphiorignore } from "./collect";
import { makePathExcluder, countWithoutJustification, EMPTY_CONFIG, SPHIORIGNORE_FILE } from "./suppress";
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

/** 値を取るフラグ。値が無ければ引数不正。 */
const VALUE_FLAGS = new Set(["sarif", "json", "fix-context", "suppressed", "fail-on"]);
/** 値を取らないフラグ。 */
const BOOLEAN_FLAGS = new Set(["no-ignore-file"]);

type ParsedFlags = { ok: true; flags: Record<string, string> } | { ok: false; error: string };

/**
 * フラグを厳密に解釈する。
 *
 * 以前は未知のフラグ・`--fail-on` の不正値（`bogus`・値なし）を黙って捨てていた。
 * CI で `--fail-on` を打ち間違えると閾値が無効になり、重大な所見があっても
 * exit 0 で「合格」になる（ゲートが黙って外れる）。これは「0 件走査を緑にしない」
 * （下の dir_not_found）と同じ種類の事故なので、解釈できない引数は exit 2 にする。
 *
 * 受け付ける形: `--flag value` と `--flag=value`。`--fail-on` の値は大文字小文字を問わない
 * （`HIGH` は意図が明らかなので正規化して受ける）。
 */
function parseFlags(rest: string[]): ParsedFlags {
  const flags: Record<string, string> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith("--")) return { ok: false, error: `unexpected argument: ${a}` };
    const eq = a.indexOf("=");
    const key = eq >= 0 ? a.slice(2, eq) : a.slice(2);
    if (BOOLEAN_FLAGS.has(key)) {
      if (eq >= 0) return { ok: false, error: `--${key} takes no value` };
      flags[key] = "true";
      continue;
    }
    if (!VALUE_FLAGS.has(key)) return { ok: false, error: `unknown option: --${key}` };
    let val: string | undefined;
    if (eq >= 0) val = a.slice(eq + 1);
    else if (rest[i + 1] !== undefined && !rest[i + 1].startsWith("--")) val = rest[++i];
    if (!val) return { ok: false, error: `--${key} needs a value` };
    if (key === "fail-on") {
      val = val.toLowerCase();
      if (!(val in SEV_ORDER)) return { ok: false, error: `--fail-on must be one of: critical, high, medium, low, info (got "${val}")` };
    }
    flags[key] = val;
  }
  return { ok: true, flags };
}

/** テスト可能な CLI 本体。exitCode を返す（process.exit は bin 側）。 */
export function runCli(argv: string[], ctx: CliContext = {}): CliResult {
  const log = ctx.log ?? (() => {});
  const logErr = ctx.logErr ?? log;
  const writeFile = ctx.writeFile ?? ((p, d) => writeFileSync(p, d));
  const [cmd, dir, ...rest] = argv;

  if (cmd !== "run" || !dir) {
    logErr("usage: sphior-scan run <dir> [--sarif out.sarif] [--json out.json] [--fix-context out.json] [--suppressed out.json] [--fail-on high] [--no-ignore-file]");
    return { exitCode: 2, error: "bad_args" };
  }

  const parsed = parseFlags(rest);
  if (!parsed.ok) {
    // 解釈できない引数で走査を進めると、意図した閾値・出力が効かないまま結果が出る。
    logErr(`error: ${parsed.error}`);
    logErr("  Nothing was scanned. Fix the command so the result means what you intended.");
    return { exitCode: 2, error: "bad_args" };
  }
  const flags = parsed.flags;

  // 走査対象が存在しないのに「0 findings・exit 0」を返すと、CI のパス打ち間違いが
  // 永久に緑になる。「0 件検出」と「0 件走査」は別物として扱う
  // （証跡側で collection_failure / heartbeat を分けているのと同じ原則）。
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    logErr(`error: directory not found: ${dir}`);
    logErr("  Nothing was scanned, so this is not a clean result. Check the path.");
    return { exitCode: 2, error: "dir_not_found" };
  }

  // `.sphiorignore`: パス除外は収集時に、ルール限定の抑制は runScan 側に渡す。
  // 「見なかった」と「見たが受け入れた」を分けて数えるため、除外はここで数える。
  const ignoreCfg = flags["no-ignore-file"] ? EMPTY_CONFIG : readSphiorignore(dir);
  const isExcluded = makePathExcluder(ignoreCfg);
  let excludedCount = 0;
  const exclude = (relPath: string) => {
    if (!isExcluded(relPath)) return false;
    excludedCount++;
    return true;
  };

  for (const p of ignoreCfg.problems) {
    logErr(`warning: ${SPHIORIGNORE_FILE}:${p.line}: ${p.reason} — ignored this line (“${p.text}”)`);
  }

  const files = collectSourceFiles(dir, { exclude });
  const result = runScan({ files, suppress: ignoreCfg });
  const sarifJson = canonicalJson(result.sarif);

  if (flags.sarif) writeFile(flags.sarif, sarifJson);
  // `--json` の形は変えない（公開 CLI の出力なので配列のまま）。抑制分は別フラグで出す
  // （SARIF には載せない理由は run.ts の注記参照）。
  if (flags.json) writeFile(flags.json, canonicalJson(result.findings));
  if (flags.suppressed) writeFile(flags.suppressed, canonicalJson(result.suppressed));
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
  // 「見なかった(excluded)」と「見たが受け入れた(suppressed)」を件数として明示する。
  // どちらも 0 件扱いに丸めない（丸めると「きれいでした」が何も意味しなくなる）。
  const scope =
    (excludedCount > 0 ? ` ${excludedCount} files excluded` : "") +
    (result.suppressed.length > 0 ? `${excludedCount > 0 ? "," : ""} ${result.suppressed.length} suppressed` : "");
  logErr(
    `SPHIOR CODE: ${result.findings.length} findings ` +
      `(critical=${counts.critical ?? 0} high=${counts.high ?? 0} medium=${counts.medium ?? 0} low=${counts.low ?? 0}) ` +
      `${files.length} files scanned${scope ? ` •${scope}` : ""} ` +
      `engine=${result.engine_version} ruleset=${result.ruleset_version}`,
  );

  // 理由の無い抑制は静かに溜まる。責めずに数だけ出す（後から棚卸しできるように）
  const unexplained = countWithoutJustification(result.suppressed);
  if (unexplained > 0) {
    logErr(`  note: ${unexplained} of the suppressions carry no reason. Add \`: why\` to the comment, or \`# why\` to the ${SPHIORIGNORE_FILE} line, so an auditor can read it later.`);
  }

  // 端末実行では「次に何ができるか」を示す（SARIF を読ませるより先に用途を伝える）。
  if (ctx.isTty && !flags.sarif && !flags.json && !flags["fix-context"]) {
    logErr("");
    logErr("  --fix-context fc.json   hand findings to an AI agent to fix");
    logErr("  --sarif out.sarif       for GitHub code scanning / CI dashboards");
    logErr("  --fail-on high          exit 1 if anything at or above this severity (CI)");
    logErr(`  ${SPHIORIGNORE_FILE}            exclude paths, or accept a rule with a reason`);
  }

  let exitCode = 0;
  // parseFlags で妥当な重大度に正規化済み（不正値はここまで来ない）。
  const failOn = flags["fail-on"] as Severity | undefined;
  if (failOn) {
    const threshold = SEV_ORDER[failOn];
    if (result.findings.some((f) => SEV_ORDER[f.severity] >= threshold)) exitCode = 1;
  }
  return { exitCode, result, sarifJson };
}
