/**
 * detect.ts — CWE パターン検出（決定論・設計 §4.1 SAST-pattern / P1-4）
 *
 * 言語スコープ付き正規表現でマッチし、コメント行はヒューリスティックで除外。
 * fingerprint はマッチ実体のハッシュを locator にして行ズレに強い。
 */

import type { CanonicalFinding } from "../types";
import { SCHEMA_VERSION } from "../types";
import { sha256, canonicalHash } from "../canonical";
import { PATTERN_RULES, type PatternRule } from "./rules";
import { parseJs, detectPatternsFromAst, isAstJs, AST_JS_RULE_IDS } from "./ast-js";
import { detectTaintFromAst } from "./taint-js";
import { getAstBackend } from "./ast-backend";

export interface PatternOptions {
  allowFingerprints?: Set<string>;
  ignorePaths?: RegExp[];
}

function extOf(path: string): string {
  const base = path.split("/").pop() ?? path;
  const dot = base.lastIndexOf(".");
  return dot >= 0 ? base.slice(dot + 1).toLowerCase() : "";
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return starts;
}
function toPos(starts: number[], index: number): { line: number; col: number; lineStart: number } {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, col: index - starts[lo] + 1, lineStart: starts[lo] };
}

// マッチ位置がその行のコメント以降にあるか（素朴だが FP を大幅に減らす）。
function inLineComment(text: string, lineStart: number, matchIndex: number, isPython: boolean): boolean {
  const before = text.slice(lineStart, matchIndex);
  const marker = isPython ? before.indexOf("#") : before.indexOf("//");
  if (marker < 0) return false;
  // クオート内の # / // は除外（超素朴）
  const upto = before.slice(0, marker);
  const quotes = (upto.match(/["'`]/g) ?? []).length;
  return quotes % 2 === 0;
}

/**
 * その行自体がブロックコメントの一部か（`/* …`・JSDoc の継続行 `* …`）。
 *
 * 実測で、「Math.random() 等 non-deterministic 関数禁止」と**禁止事項を書いた
 * JSDoc 行**が pattern.js.weak_random として上がっていた。危険なコードを探す
 * ルールが、危険なコードを禁止する文章に当たっている状態。
 *
 * ブロックコメントの範囲を text 全体で追うやり方は採らない。文字列や正規表現の
 * 中の `/*` を誤って開始と見なすと、次の `*​/` までの**実コードを丸ごと見逃す**
 * （検出漏れは誤検知より悪い）。判定を「マッチした行の先頭」だけに閉じる。
 *
 * `*` の後に空白か `/` を要求するのは、オブジェクトリテラルのジェネレータ
 * （`*gen() { … }`）を誤ってコメント扱いしないため。
 */
function isBlockCommentLine(text: string, lineStart: number): boolean {
  const lineEnd = text.indexOf("\n", lineStart);
  const line = text.slice(lineStart, lineEnd < 0 ? text.length : lineEnd).trimStart();
  return line.startsWith("/*") || /^\*(\s|\/|$)/.test(line);
}

export function detectPatterns(path: string, text: string, opts: PatternOptions = {}): CanonicalFinding[] {
  if (opts.ignorePaths?.some((re) => re.test(path))) return [];
  const ext = extOf(path);
  const isPython = ext === "py";
  const starts = lineStarts(text);
  const out: CanonicalFinding[] = [];
  const seen = new Set<string>();

  // JS/TS は AST で高精度検出（文字列/コメント内の擬似マッチを排除）。
  // parse 成功時のみ AST 対象ルールを regex から除外する（失敗時は regex にフォールバック）。
  let astHandled: Set<string> | null = null;
  if (isAstJs(ext)) {
    const ast = parseJs(text); // parse を pattern/taint で共有
    if (ast) {
      astHandled = AST_JS_RULE_IDS;
      const astFindings = [
        ...detectPatternsFromAst(ast, path, text),
        ...detectTaintFromAst(ast, path, text), // Tier 4: source→sink
      ];
      for (const f of astFindings) {
        if (opts.allowFingerprints?.has(f.fingerprint) || seen.has(f.fingerprint)) continue;
        seen.add(f.fingerprint);
        out.push(f);
      }
    }
  }

  // 非 JS/TS 言語（Python/Go/Ruby/PHP…）は登録済み tree-sitter バックエンドを優先（未登録は regex）。
  let backendHandled: Set<string> | null = null;
  if (!isAstJs(ext)) {
    const backend = getAstBackend(ext);
    if (backend) {
      backendHandled = backend.coveredRuleIds;
      for (const f of backend.detect(path, text)) {
        if (opts.allowFingerprints?.has(f.fingerprint) || seen.has(f.fingerprint)) continue;
        seen.add(f.fingerprint);
        out.push(f);
      }
    }
  }

  const applicable = PATTERN_RULES.filter((r) => r.exts.includes(ext) && !astHandled?.has(r.id) && !backendHandled?.has(r.id));
  for (const rule of applicable) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const idx = m.index;
      const pos = toPos(starts, idx);
      if (inLineComment(text, pos.lineStart, idx, isPython) || isBlockCommentLine(text, pos.lineStart)) {
        if (re.lastIndex === idx) re.lastIndex++;
        continue;
      }
      const matched = m[0];
      const end = toPos(starts, idx + matched.length);
      const locator = sha256(`${rule.id}:${matched}`);
      const fingerprint = canonicalHash({ rule_id: rule.id, path, locator });
      if (opts.allowFingerprints?.has(fingerprint) || seen.has(fingerprint)) {
        if (re.lastIndex === idx) re.lastIndex++;
        continue;
      }
      seen.add(fingerprint);
      out.push(buildFinding(rule, path, pos, end, fingerprint));
      if (re.lastIndex === idx) re.lastIndex++;
    }
  }

  out.sort((a, b) => {
    if (a.location.start_line !== b.location.start_line) return a.location.start_line - b.location.start_line;
    if (a.location.start_col !== b.location.start_col) return a.location.start_col - b.location.start_col;
    return a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0;
  });
  return out;
}

function buildFinding(
  rule: PatternRule,
  path: string,
  start: { line: number; col: number },
  end: { line: number; col: number },
  fingerprint: string,
): CanonicalFinding {
  return {
    schema_version: SCHEMA_VERSION,
    kind: "sast_pattern",
    rule_id: rule.id,
    cwe: rule.cwe,
    owasp: rule.owasp,
    severity: rule.severity,
    confidence: rule.confidence ?? "likely",
    title: rule.title,
    message: rule.message,
    location: { path, start_line: start.line, start_col: start.col, end_line: end.line, end_col: end.col },
    // pattern は秘密でないので、マッチ位置由来の識別だけを保持（生ソースは載せない）
    snippet_hash: fingerprint,
    remediation: rule.remediation,
    references: rule.references,
    fingerprint,
  };
}

export function detectPatternsInFiles(
  files: Array<{ path: string; text: string }>,
  opts: PatternOptions = {},
): CanonicalFinding[] {
  const all: CanonicalFinding[] = [];
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    all.push(...detectPatterns(f.path, f.text, opts));
  }
  return all;
}
