#!/usr/bin/env node
/**
 * scan-on-write.mjs — AI のエージェントがファイルを書くたびに、そのファイルだけを SPHIOR CODE で検査する（2026-11-15）
 *
 * 1 本の台本で 3 つのツールのフックに答える（Cursor は引数 `cursor` で呼ぶ・他は入力の tool_name で見分ける）:
 *
 *   Claude Code  PostToolUse（Write / Edit / MultiEdit の後）
 *                入力 tool_input.file_path → 所見があれば標準エラーに書いて exit 2（エージェントに返る）
 *   Codex        PostToolUse（apply_patch の後。matcher の Edit / Write は apply_patch の別名）
 *                入力 tool_input.command（パッチの本文）から書いたファイルを拾う
 *                → 所見は hookSpecificOutput.additionalContext で添える（exit 0）。Codex は exit 2 を
 *                  「編集が止められた」と受け取り、保存済みなのに「何も変更していない」と答えてしまうため
 *   Cursor       postToolUse（書く道具の後）。入力 tool_input.file_path
 *                → 所見は { additional_context } で道具の結果の後に添える（exit 0）
 *                afterFileEdit＋stop の型は、Cursor の CLI の一回きりの実行で stop が呼ばれないため使わない
 *
 * 何も無ければ黙る（会話を汚さない）。検査そのものが動かなかった時（npx が無い・初回の取得ができない等）は
 * エージェントの作業を止めず、「検査しなかった」ことだけを一行出す。「検査して 0 件」と「検査していない」を混ぜないため。
 *
 * 設定（環境変数・任意）:
 *   SPHIOR_GUARD_FAIL_ON  返す重大度の下限。critical / high（既定）/ medium / low
 *   SPHIOR_GUARD_DISABLE  1 で無効
 *   SPHIOR_SCAN_BIN       検査の CLI の場所（開発用。既定は npx で版を固定して取得）
 * プロジェクトで除外したい物は、いつもどおり `.sphiorignore` に書く（CLI がそのまま尊重する）。
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";

// 検査の CLI の版は固定する（毎回同じ規則で検査し、知らないうちに中身が変わらないように）
const SCAN_PACKAGE = "@sphior/scan@0.1.11";
const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
// 1 回に返す所見の数の上限（エージェントの文脈を溢れさせない。残りは件数で伝える）
const MAX_REPORTED = 10;
// 1 ファイルの検査の時間の上限。初回は npx の取得が入るので長めにとる（フック自体の上限は hooks の timeout 側）
const SCAN_TIMEOUT_MS = 50_000;

function readStdin() {
  try {
    return JSON.parse(readFileSync(0, "utf8"));
  } catch {
    return null;
  }
}

function main() {
  if (process.env.SPHIOR_GUARD_DISABLE === "1") return finish(0);
  const input = readStdin();
  if (!input) return finish(0);

  if (process.argv[2] === "cursor") return cursorPostToolUse(input);
  return postToolUse(input);
}

// ── Claude Code・Codex: 書いた直後に検査し、所見は exit 2 で返す ────────────────
function postToolUse(input) {
  const cwd = typeof input.cwd === "string" && input.cwd ? input.cwd : process.cwd();
  const files = writtenFiles(input.tool_input).map((p) => resolve(cwd, p)).filter((p) => existsSync(p));
  if (files.length === 0) return finish(0);

  const { report, notScanned } = scanAll(files, cwd);
  for (const line of notScanned) process.stderr.write(`${line}\n`);
  if (!report) return finish(0);
  if (input.tool_name === "apply_patch") {
    return reply({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: report } });
  }
  process.stderr.write(report);
  return finish(2);
}

/** 書かれたファイルを拾う。Claude Code は file_path、Codex の apply_patch はパッチの本文から */
function writtenFiles(toolInput) {
  if (!toolInput || typeof toolInput !== "object") return [];
  if (typeof toolInput.file_path === "string" && toolInput.file_path) return [toolInput.file_path];
  const patch = typeof toolInput.command === "string" ? toolInput.command : typeof toolInput.input === "string" ? toolInput.input : "";
  const paths = new Set();
  // apply_patch の書式: `*** Add File: <path>` / `*** Update File: <path>` / `*** Move to: <path>`（削除は検査しない）
  for (const m of patch.matchAll(/^\*\*\* (?:Add File|Update File|Move to): (.+)$/gm)) paths.add(m[1].trim());
  // Update の後に Move した時は、移動元は残らないので移動先だけを見る
  for (const m of patch.matchAll(/^\*\*\* Update File: (.+)\n\*\*\* Move to: /gm)) paths.delete(m[1].trim());
  return [...paths];
}

// ── Cursor: 編集の直後（postToolUse）に検査し、所見は additional_context で添える ──────────
/**
 * Cursor の CLI の一回きりの実行では stop が呼ばれない（2026-11-15 に実機で確認）ため、編集の直後に返す。
 * postToolUse は読むだけの道具（Read 等）でも file_path を持つので、書く道具だけに絞る。
 */
const CURSOR_WRITE_TOOLS = /^(Write|Edit|MultiEdit|StrReplace|search_replace|edit_file)$/;

function cursorPostToolUse(input) {
  if (!CURSOR_WRITE_TOOLS.test(String(input.tool_name || ""))) return reply({});
  const roots = Array.isArray(input.workspace_roots) ? input.workspace_roots : [];
  const cwd = (typeof input.cwd === "string" && input.cwd) || (typeof roots[0] === "string" && roots[0]) || process.env.CURSOR_PROJECT_DIR || process.cwd();
  const files = writtenFiles(input.tool_input).map((p) => resolve(cwd, p)).filter((p) => existsSync(p));
  if (files.length === 0) return reply({});

  const { report, notScanned } = scanAll(files, cwd);
  for (const line of notScanned) process.stderr.write(`${line}\n`);
  return reply(report ? { additional_context: report } : {});
}

function reply(obj) {
  process.stdout.write(JSON.stringify(obj));
  return finish(0);
}

// ── 検査（3 つのツールで共通） ────────────────────────────────────────────────
/** 各ファイルを検査し、閾値以上の所見をまとめた報告（無ければ null）と、検査できなかったファイルの一行を返す */
function scanAll(files, cwd) {
  const failOn = (process.env.SPHIOR_GUARD_FAIL_ON || "high").toLowerCase();
  const threshold = SEVERITY_ORDER[failOn] ?? SEVERITY_ORDER.high;
  const byFile = [];
  const notScanned = [];
  for (const file of files) {
    const res = scanFile(file, cwd);
    if (res.error) {
      notScanned.push(`SPHIOR CODE: ${displayPath(file, cwd)} was not scanned (${res.error}).`);
      continue;
    }
    const hits = res.findings
      .filter((f) => (SEVERITY_ORDER[f.severity] ?? 0) >= threshold)
      .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.location.start_line - b.location.start_line);
    if (hits.length > 0) byFile.push({ shown: displayPath(file, cwd), hits });
  }
  return { report: byFile.length > 0 ? formatReport(byFile) : null, notScanned };
}

/** `@sphior/scan run <file> --json` で 1 ファイルを検査する。結果は一時フォルダの JSON で受け取る（標準出力は SARIF が流れるので使わない） */
function scanFile(file, cwd) {
  const work = mkdtempSync(join(tmpdir(), "sphior-guard-"));
  const out = join(work, "findings.json");
  try {
    const bin = process.env.SPHIOR_SCAN_BIN;
    const [cmd, args] = bin
      ? [process.execPath, [bin, "run", file, "--json", out]]
      : ["npx", ["-y", SCAN_PACKAGE, "run", file, "--json", out]];
    const res = spawnSync(cmd, args, { cwd, encoding: "utf8", timeout: SCAN_TIMEOUT_MS, stdio: ["ignore", "ignore", "pipe"] });
    try {
      return { findings: JSON.parse(readFileSync(out, "utf8")) };
    } catch {
      // 結果の JSON が無い＝検査が動かなかった。理由は「error」を含む行を優先する（node のスタックの 1 行目は場所しか言わないため）
      const errLines = (res.stderr || "").split("\n").map((l) => l.trim()).filter(Boolean);
      return { error: res.error ? res.error.message : errLines.find((l) => /error/i.test(l)) || errLines[0] || `exit ${res.status}` };
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** 作業ディレクトリの中なら相対パスで見せる（エージェントにも人にも読みやすい） */
function displayPath(filePath, cwd) {
  const rel = relative(cwd, filePath);
  return rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel : filePath;
}

/** エージェントが読んでそのまま直せる形にする。秘密の値そのものは CLI の時点で出てこない（伏せた形のみ） */
function formatReport(byFile) {
  const total = byFile.reduce((n, f) => n + f.hits.length, 0);
  const where = byFile.length === 1 ? byFile[0].shown : `${byFile.length} files`;
  const lines = [
    `Your edit was saved, but SPHIOR CODE found ${total} security issue${total === 1 ? "" : "s"} in ${where}. Fix ${total === 1 ? "it" : "them"} now; the file is scanned again on your next edit.`,
    "",
  ];
  let shownCount = 0;
  for (const { shown, hits } of byFile) {
    if (byFile.length > 1) lines.push(`${shown}:`);
    for (const f of hits) {
      if (shownCount >= MAX_REPORTED) break;
      shownCount++;
      const cwe = f.cwe ? ` (${f.cwe})` : "";
      lines.push(`- [${f.severity}] line ${f.location.start_line}: ${f.title}${cwe}`);
      if (f.message && f.message !== f.title) lines.push(`  Why: ${f.message}`);
      if (f.remediation) lines.push(`  Fix: ${f.remediation}`);
    }
  }
  if (total > shownCount) lines.push(`- …and ${total - shownCount} more. Run \`npx ${SCAN_PACKAGE} run <file>\` to see all.`);
  lines.push(
    "",
    "If a finding is a false positive, explain why to the user instead of working around the rule, and suggest adding it to .sphiorignore.",
    "If a secret was hard-coded, move it to an environment variable and tell the user to rotate the exposed value.",
    "",
  );
  return lines.join("\n");
}

function finish(code) {
  process.exitCode = code;
}

main();
