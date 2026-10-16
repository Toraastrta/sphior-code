/**
 * local-scan.ts — API キー無しで動く経路（local モード）
 *
 * 同梱の決定論エンジン（@sphior/scan の CLI）でワークスペースを走査し、
 * get_fix_context が返すのと同じ FixContext[] を組み立てる。
 *
 * なぜ CLI を子プロセスで呼ぶのか:
 *   @sphior/scan は bin のみを公開しており、ライブラリ入口(main/exports)を持たない。
 *   CLI は既に `--fix-context out.json` を実装しているため、ここを使うのが
 *   「同じエンジン・同じ出力」を保証する最短経路になる（実装を二重化しない）。
 *
 * データ境界: ソースはローカルから出ない。SPHIOR のサーバーには一切問い合わせない。
 */

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve as resolvePath } from "node:path";
import { createRequire } from "node:module";
import { log } from "./logger.js";

const require_ = createRequire(import.meta.url);

/** CLI の実体を解決する。依存として入っているので require.resolve で足りる。 */
function resolveCli(): string {
  try {
    return require_.resolve("@sphior/scan/dist/cli.js");
  } catch {
    throw new Error(
      "Local scan engine (@sphior/scan) not found.\n" +
      "  Reinstall with `npm i -g sphior-code-mcp`, or set SPHIOR_API_KEY to use cloud mode.",
    );
  }
}

/** 走査対象ディレクトリ。引数 > SPHIOR_WORKSPACE > cwd。 */
export function resolveWorkspace(path?: string): string {
  return resolvePath(path || process.env.SPHIOR_WORKSPACE?.trim() || process.cwd());
}

export interface LocalScanResult {
  mode: "local";
  workspace: string;
  total: number;
  /** severity フィルタ適用後に返す FixContext 群。 */
  fix_contexts: unknown[];
  note: string;
}

/**
 * ワークスペースを走査して FixContext[] を返す。
 * findingId / severity が指定されていれば絞り込む（cloud 版と同じ意味論）。
 */
export async function localFixContext(opts: {
  path?: string;
  findingId?: string;
  severity?: string;
  timeoutMs: number;
}): Promise<LocalScanResult> {
  const cli = resolveCli();
  const workspace = resolveWorkspace(opts.path);
  const tmp = mkdtempSync(join(tmpdir(), "sphior-mcp-"));
  const outFile = join(tmp, "fix-context.json");

  try {
    await runCli(cli, [workspace, "--fix-context", outFile], opts.timeoutMs);

    let all: unknown[] = [];
    try {
      all = JSON.parse(readFileSync(outFile, "utf8")) as unknown[];
    } catch {
      all = []; // 検出ゼロなら CLI がファイルを書かないことがある
    }

    const filtered = all.filter((c) => {
      const x = c as { finding_id?: string; severity?: string };
      if (opts.findingId && x.finding_id !== opts.findingId) return false;
      if (opts.severity && x.severity !== opts.severity) return false;
      return true;
    });

    return {
      mode: "local",
      workspace,
      total: filtered.length,
      fix_contexts: filtered,
      note:
        "Scanned with the local deterministic engine; no SPHIOR server was contacted. " +
        "Open each finding's location in the workspace and apply its remediation_steps. " +
        "Set SPHIOR_API_KEY if you need tamper-evident evidence, history, or GRC integration.",
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** CLI を子プロセスで実行する（stdout は使わず、成果物ファイルを読む）。 */
function runCli(cli: string, args: string[], timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [cli, "run", ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    p.stderr.on("data", (d) => { stderr += String(d); });

    const timer = setTimeout(() => {
      p.kill("SIGKILL");
      reject(new Error(`Local scan timed out after ${timeoutMs}ms. Raise SPHIOR_TIMEOUT or narrow the scan path.`));
    }, timeoutMs);

    p.on("error", (e) => { clearTimeout(timer); reject(e); });
    p.on("close", (code) => {
      clearTimeout(timer);
      // --fail-on を渡していないので 0 以外は実行時エラー扱い
      if (code === 0) return resolve();
      log.error("local scan failed", { code, stderr: stderr.slice(0, 500) });
      reject(new Error(`Local scan failed (exit ${code}): ${stderr.slice(0, 300)}`));
    });
  });
}
