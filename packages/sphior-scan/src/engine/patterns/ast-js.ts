/**
 * ast-js.ts — JS/TS の AST ベース検出（Tier 3・Semgrep 級への第一歩）
 *
 * 正規表現は「文字列/コメントの中の eval(」も拾って誤検知するが、AST は
 * それが本当に CallExpression（関数呼び出し）かを構文的に判定するため
 * FP を大幅に排除する。parse 失敗時は null を返し、呼び出し側が regex へ
 * フォールバックする（検知漏れを作らない）。
 *
 * 決定論・再現性は不変（同一入力→同一 AST→同一 finding）。
 */

import { parse } from "@babel/parser";
import type { CanonicalFinding } from "../types";
import { SCHEMA_VERSION } from "../types";
import { sha256, canonicalHash } from "../canonical";
import { PATTERN_RULES } from "./rules";

/** AST が担当する rule id（regex 版は JS/TS で無効化される）。 */
export const AST_JS_RULE_IDS = new Set<string>([
  "pattern.js.eval",
  "pattern.js.new_function",
  "pattern.js.settimeout_string",
  "pattern.js.child_process_shell",
  "pattern.js.react_dangerous_html",
]);

const RULE_BY_ID = new Map(PATTERN_RULES.map((r) => [r.id, r]));
const JS_EXTS = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs"]);

export function isAstJs(ext: string): boolean {
  return JS_EXTS.has(ext);
}

export interface AstNode {
  type: string;
  start?: number;
  end?: number;
  loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
  callee?: AstNode;
  name?: string;
  arguments?: AstNode[];
  [k: string]: unknown;
}

const SKIP_KEYS = new Set(["loc", "leadingComments", "trailingComments", "comments", "tokens", "range"]);

export function walk(node: unknown, visit: (n: AstNode) => void): void {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const child of node) walk(child, visit);
    return;
  }
  const obj = node as Record<string, unknown>;
  if (typeof obj.type === "string") visit(obj as AstNode);
  for (const key of Object.keys(obj)) {
    if (SKIP_KEYS.has(key)) continue;
    walk(obj[key], visit);
  }
}

export function calleeName(node: AstNode): string | null {
  const callee = node.callee;
  return callee && callee.type === "Identifier" && typeof callee.name === "string" ? callee.name : null;
}

/** callee のメソッド名（Identifier もしくは obj.method の method）。 */
export function calleeMethodName(node: AstNode): string | null {
  const callee = node.callee;
  if (!callee) return null;
  if (callee.type === "Identifier" && typeof callee.name === "string") return callee.name;
  if (callee.type === "MemberExpression") {
    const prop = callee.property as AstNode | undefined;
    if (prop && prop.type === "Identifier" && typeof prop.name === "string") return prop.name;
  }
  return null;
}

/** 引数が「連結 / 補間」で動的か（静的文字列は安全とみなす）。 */
function isConcatOrInterp(arg: AstNode | undefined): boolean {
  if (!arg) return false;
  if (arg.type === "TemplateLiteral") return ((arg.expressions as unknown[] | undefined)?.length ?? 0) > 0;
  if (arg.type === "BinaryExpression") return arg.operator === "+";
  return false;
}

/** dangerouslySetInnerHTML の __html が動的（＝リテラルでない）か。 */
function dangerousHtmlIsDynamic(attr: AstNode): boolean {
  const value = attr.value as AstNode | undefined;
  if (!value || value.type !== "JSXExpressionContainer") return true; // 不明→保守的に flag
  const expr = value.expression as AstNode | undefined;
  if (!expr || expr.type !== "ObjectExpression") return true;
  const props = (expr.properties as AstNode[] | undefined) ?? [];
  for (const p of props) {
    const key = p.key as AstNode | undefined;
    const keyName = key ? ((key.name as string | undefined) ?? (key.value as string | undefined)) : undefined;
    if (keyName === "__html") {
      const v = p.value as AstNode | undefined;
      return !(v && v.type === "StringLiteral"); // 静的 HTML リテラルは安全→非検知
    }
  }
  return true;
}

/** JS/TS を AST に parse（失敗は null）。pattern/taint 検出で共有する。 */
export function parseJs(text: string): unknown | null {
  try {
    return parse(text, {
      sourceType: "unambiguous",
      errorRecovery: true,
      plugins: ["typescript", "jsx", "decorators-legacy"],
    });
  } catch {
    return null;
  }
}

/** parse 済み AST からパターンを検出（parse を共有するため ast を受ける）。 */
export function detectPatternsFromAst(ast: unknown, path: string, text: string): CanonicalFinding[] {
  const out: CanonicalFinding[] = [];
  const seen = new Set<string>();

  const add = (ruleId: string, node: AstNode): void => {
    const rule = RULE_BY_ID.get(ruleId);
    if (!rule || !node.loc) return;
    const snippet =
      node.start != null && node.end != null ? text.slice(node.start, Math.min(node.end, node.start + 60)) : ruleId;
    const locator = sha256(`${ruleId}:${snippet}`);
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator });
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    out.push({
      schema_version: SCHEMA_VERSION,
      kind: "sast_pattern",
      rule_id: rule.id,
      cwe: rule.cwe,
      owasp: rule.owasp,
      severity: rule.severity,
      confidence: "confirmed", // AST 確定 → 高信頼
      title: rule.title,
      message: rule.message,
      location: {
        path,
        start_line: node.loc.start.line,
        start_col: node.loc.start.column + 1,
        end_line: node.loc.end.line,
        end_col: node.loc.end.column + 1,
      },
      snippet_hash: fingerprint,
      remediation: rule.remediation,
      references: rule.references,
      fingerprint,
    });
  };

  walk(ast, (node) => {
    if (node.type === "CallExpression") {
      const name = calleeName(node);
      if (name === "eval") {
        add("pattern.js.eval", node);
      } else if (name === "setTimeout" || name === "setInterval") {
        const first = node.arguments?.[0];
        if (first && (first.type === "StringLiteral" || first.type === "TemplateLiteral")) {
          add("pattern.js.settimeout_string", node);
        }
      }
      // child_process exec/execSync に「連結/補間」の動的コマンド → OS command injection
      const method = calleeMethodName(node);
      if ((method === "exec" || method === "execSync") && isConcatOrInterp(node.arguments?.[0])) {
        add("pattern.js.child_process_shell", node);
      }
    } else if (node.type === "NewExpression") {
      if (calleeName(node) === "Function") add("pattern.js.new_function", node);
    } else if (node.type === "JSXAttribute") {
      const name = node.name as AstNode | undefined;
      if (name && name.type === "JSXIdentifier" && name.name === "dangerouslySetInnerHTML") {
        // 静的 HTML リテラルは非検知、動的 __html のみ検出（FP 抑制）
        if (dangerousHtmlIsDynamic(node)) add("pattern.js.react_dangerous_html", node);
      }
    }
  });

  out.sort((a, b) =>
    a.location.start_line !== b.location.start_line
      ? a.location.start_line - b.location.start_line
      : a.location.start_col !== b.location.start_col
        ? a.location.start_col - b.location.start_col
        : a.rule_id < b.rule_id
          ? -1
          : a.rule_id > b.rule_id
            ? 1
            : 0,
  );
  return out;
}

/** 後方互換ラッパ: parse + パターン検出。parse 失敗は null。 */
export function detectPatternsAstJs(path: string, text: string): CanonicalFinding[] | null {
  const ast = parseJs(text);
  return ast ? detectPatternsFromAst(ast, path, text) : null;
}
