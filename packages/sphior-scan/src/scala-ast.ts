/**
 * scala-ast.ts — Scala の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * JVM 系（Play/Akka HTTP/Spring）。source = request.getParameter / queryString /
 * params。multi-level inter-procedural taint（command/SQL injection・path
 * traversal・SSRF）を検出。java/kotlin-ast と同型。engine core / Next には非依存。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { SCALA_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
import { registerAstBackend } from "./engine/patterns/ast-backend";
import type { CanonicalFinding, Severity } from "./engine/types";
import { SCHEMA_VERSION } from "./engine/types";
import { sha256, canonicalHash } from "./engine/canonical";

interface TsNode {
  type: string; text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  childCount: number; child(i: number): TsNode | null;
  namedChildCount: number; namedChild(i: number): TsNode | null;
  childForFieldName(name: string): TsNode | null;
}

interface SRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const S_RULES: Record<string, SRule> = {
  "taint.scala.command_injection": { id: "taint.scala.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → exec/Process)", message: "Untrusted request input flows into Runtime.exec/Process — OS command injection.", remediation: "Use a fixed command with validated Seq[String] args; never build shell strings.", references: REF("78") },
  "taint.scala.sql_injection": { id: "taint.scala.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → query)", message: "Untrusted input is concatenated into a SQL statement (executeQuery/execute).", remediation: "Use parameterized queries / prepared statements.", references: REF("89") },
  "taint.scala.path_traversal": { id: "taint.scala.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → file access)", message: "Untrusted input controls a filesystem path (Source.fromFile/new File).", remediation: "Validate against an allowed base dir; reject '..'.", references: REF("22") },
  "taint.scala.ssrf": { id: "taint.scala.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → request URL)", message: "Untrusted input controls an outbound URL (Source.fromURL/HTTP client).", remediation: "Allowlist hosts/schemes.", references: REF("918") },
};

const S_SOURCE_SUFFIXES = [".getParameter", ".getParameterValues", ".getHeader", ".getQueryString", ".queryString", ".body"];
const S_SCOPE_TYPES = new Set(["function_definition"]);
const S_SQL = new Set(["executeQuery", "execute", "executeUpdate", "prepareStatement"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function sMethodName(fn: TsNode | null): string {
  if (!fn) return "";
  if (fn.type === "field_expression") return fn.childForFieldName("field")?.text ?? "";
  return fn.text;
}
function sIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  const t = node.text;
  return S_SOURCE_SUFFIXES.some((s) => t.endsWith(s) || t.includes(`${s}(`)) || (node.type === "field_expression" && t.endsWith(".params"));
}
function sTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "identifier": return tainted.has(node.text);
    case "call_expression": return sIsSource(node) || sTainted(node.childForFieldName("function"), tainted);
    case "field_expression": return sIsSource(node) || sTainted(node.childForFieldName("value") ?? node.namedChild(0), tainted);
    case "infix_expression": return sTainted(node.childForFieldName("left"), tainted) || sTainted(node.childForFieldName("right"), tainted);
    case "interpolated_string_expression": case "string": {
      let f = false;
      const rec = (n: TsNode): void => { if (f) return; if (n.type === "interpolation") { for (let i = 0; i < n.namedChildCount; i++) { const c = n.namedChild(i); if (c && sTainted(c, tainted)) { f = true; return; } } } for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); } };
      rec(node); return f;
    }
    case "parenthesized_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && sTainted(c, tainted)) return true; }
      return false;
    }
    default: return sIsSource(node);
  }
}
function sWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && S_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}
function sCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    sWalkScope(scope, (n) => {
      if (n.type === "val_definition" || n.type === "var_definition") {
        const name = n.childForFieldName("pattern");
        const value = n.childForFieldName("value");
        if (name && name.type === "identifier" && !tainted.has(name.text) && sTainted(value, tainted)) { tainted.add(name.text); changed = true; }
      } else if (n.type === "assignment_expression") {
        const left = n.childForFieldName("left");
        if (left && left.type === "identifier" && !tainted.has(left.text) && sTainted(n.childForFieldName("right"), tainted)) { tainted.add(left.text); changed = true; }
      }
    });
  }
  return tainted;
}
function sAnyArg(call: TsNode, tainted: Set<string>): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && sTainted(a, tainted)) return true; }
  return false;
}

// ── inter-procedural アダプタ ──
function sParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p || p.type !== "parameter") { names.push(""); continue; }
    const nm = p.childForFieldName("name") ?? p.namedChild(0);
    names.push(nm && nm.type === "identifier" ? nm.text : "");
  }
  return names;
}
function sCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "function_definition") { const name = n.childForFieldName("name"); if (name) fns.set(name.text, { params: sParamNames(n), scope: n }); }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function sCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "call_expression") return null;
  const fn = n.childForFieldName("function");
  if (!fn || fn.type !== "identifier") return null; // ローカル関数呼び出しのみ
  const args = n.childForFieldName("arguments");
  const posArgs: (TsNode | null)[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) posArgs.push(args.namedChild(i));
  return { callee: fn.text, posArgs };
}
function sScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  sWalkScope(scope, (n) => {
    if (n.type !== "call_expression") return;
    const fn = n.childForFieldName("function");
    const full = fn?.text ?? "";
    const m = sMethodName(fn);
    if (m === "exec" && sAnyArg(n, tainted)) hit("taint.scala.command_injection", n);
    else if (S_SQL.has(m) && sAnyArg(n, tainted)) hit("taint.scala.sql_injection", n);
    else if ((full.endsWith("Source.fromFile") || full === "File" || full.endsWith("Files.readAllBytes") || full.endsWith("Files.readAllLines")) && sAnyArg(n, tainted)) hit("taint.scala.path_traversal", n);
    else if ((full.endsWith("Source.fromURL") || full.endsWith("url") || m === "url") && sAnyArg(n, tainted) && S_SOURCE_SUFFIXES.every((s) => !full.endsWith(s))) hit("taint.scala.ssrf", n);
  });
  return hits;
}

function detect(path: string, text: string): CanonicalFinding[] {
  if (!parser) return [];
  let root: TsNode;
  try { root = parser.parse(text).rootNode; } catch { return []; }
  const out: CanonicalFinding[] = [];
  const seen = new Set<string>();
  const add = (ruleId: string, node: TsNode): void => {
    const rule = S_RULES[ruleId]; if (!rule) return;
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator: sha256(`${ruleId}:${node.text.slice(0, 80)}`) });
    if (seen.has(fingerprint)) return; seen.add(fingerprint);
    out.push({ schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id, cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: "likely", title: rule.title, message: rule.message, location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 }, snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint });
  };

  runInterProcTaint({
    root, moduleType: "compilation_unit", scopeTypes: S_SCOPE_TYPES,
    collectFunctions: sCollectFunctions, collectTainted: sCollectTainted, scanSinks: sScanSinks,
    exprTainted: sTainted, callTarget: sCallTarget, walkScope: sWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

export async function initScala(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(SCALA_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["scala", "sc"]), detect, coveredRuleIds: new Set() });
}
