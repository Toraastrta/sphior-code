/**
 * kotlin-ast.ts — Kotlin の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * JVM 系（Spring/Ktor/Servlet）。source=request.getParameter / call.parameters。
 * intra-procedural taint（command/SQL injection・path traversal・SSRF）。go-ast と同型。
 * Kotlin は call が navigation_expression 経由なので callee.text で識別する。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { KT_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface KRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const K_RULES: Record<string, KRule> = {
  "taint.kotlin.command_injection": { id: "taint.kotlin.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → exec/ProcessBuilder)", message: "Untrusted request input flows into Runtime.exec/ProcessBuilder — command injection.", remediation: "Use ProcessBuilder with fixed command + validated args.", references: REF("78") },
  "taint.kotlin.sql_injection": { id: "taint.kotlin.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → query)", message: "Untrusted input is concatenated into a SQL query.", remediation: "Use parameterized queries / prepared statements.", references: REF("89") },
  "taint.kotlin.path_traversal": { id: "taint.kotlin.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → File)", message: "Untrusted input controls a filesystem path (File/readText).", remediation: "Validate against an allowed base dir.", references: REF("22") },
  "taint.kotlin.ssrf": { id: "taint.kotlin.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → URL)", message: "Untrusted input controls an outbound URL.", remediation: "Allowlist hosts/schemes.", references: REF("918") },
};

const K_SOURCE_SUFFIXES = [".getParameter", ".getParameterValues", ".getHeader", ".getQueryString", ".queryParameters", ".formParameters"];
const K_SCOPE_TYPES = new Set(["function_declaration", "anonymous_function", "lambda_literal"]);
const K_SQL_SUFFIXES = [".executeQuery", ".execute", ".rawQuery", ".executeUpdate"];

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function kCallee(call: TsNode): TsNode | null { return call.namedChild(0); }
function kCalleeText(call: TsNode): string { return kCallee(call)?.text ?? ""; }
function kReceiver(call: TsNode): TsNode | null {
  const c = kCallee(call);
  return c && c.type === "navigation_expression" ? c.namedChild(0) : null;
}
function kArgExprs(call: TsNode): TsNode[] {
  const args: TsNode[] = [];
  let suffix: TsNode | null = null;
  for (let i = 0; i < call.childCount; i++) { const c = call.child(i); if (c && c.type === "call_suffix") suffix = c; }
  if (!suffix) return args;
  let va: TsNode | null = null;
  for (let i = 0; i < suffix.childCount; i++) { const c = suffix.child(i); if (c && c.type === "value_arguments") va = c; }
  if (!va) return args;
  for (let i = 0; i < va.namedChildCount; i++) {
    const a = va.namedChild(i);
    if (a && a.type === "value_argument") { const e = a.namedChild(a.namedChildCount - 1); if (e) args.push(e); }
  }
  return args;
}

function kIsSource(node: TsNode | null): boolean {
  if (!node || node.type !== "call_expression") return false;
  const t = kCalleeText(node);
  return K_SOURCE_SUFFIXES.some((s) => t.endsWith(s));
}
function kTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "simple_identifier": return tainted.has(node.text);
    case "call_expression": return kIsSource(node) || kTainted(kReceiver(node), tainted);
    case "navigation_expression": return kTainted(node.namedChild(0), tainted);
    case "additive_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && kTainted(c, tainted)) return true; }
      return false;
    }
    case "string_literal": {
      let f = false;
      const rec = (n: TsNode): void => { if (f) return; if (n.type === "simple_identifier" && tainted.has(n.text)) { f = true; return; } for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); } };
      rec(node); return f;
    }
    case "parenthesized_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && kTainted(c, tainted)) return true; }
      return false;
    }
    default: return kIsSource(node);
  }
}
function kWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && K_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}
function kCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    kWalkScope(scope, (n) => {
      if (n.type === "property_declaration") {
        let name: TsNode | null = null, value: TsNode | null = null;
        for (let i = 0; i < n.namedChildCount; i++) {
          const c = n.namedChild(i);
          if (!c) continue;
          if (c.type === "variable_declaration") name = c.namedChild(0);
          else if (c.type !== "binding_pattern_kind" && c.type !== "modifiers" && c.type !== "type_identifier") value = c;
        }
        if (name && name.type === "simple_identifier" && !tainted.has(name.text) && kTainted(value, tainted)) { tainted.add(name.text); changed = true; }
      } else if (n.type === "assignment") {
        const left = n.childForFieldName("left") ?? n.namedChild(0);
        const right = n.childForFieldName("right") ?? n.namedChild(n.namedChildCount - 1);
        if (left && left.type === "simple_identifier" && !tainted.has(left.text) && kTainted(right, tainted)) { tainted.add(left.text); changed = true; }
      }
    });
  }
  return tainted;
}

// ── inter-procedural アダプタ ──
function kParamNames(fnDef: TsNode): string[] {
  const names: string[] = [];
  let params: TsNode | null = null;
  for (let i = 0; i < fnDef.namedChildCount; i++) { const c = fnDef.namedChild(i); if (c && c.type === "function_value_parameters") { params = c; break; } }
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p || p.type !== "parameter") continue;
    let nm: TsNode | null = null;
    for (let j = 0; j < p.namedChildCount; j++) { const c = p.namedChild(j); if (c && c.type === "simple_identifier") { nm = c; break; } }
    names.push(nm ? nm.text : "");
  }
  return names;
}
function kCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "function_declaration") {
      let name: TsNode | null = null;
      for (let i = 0; i < n.namedChildCount; i++) { const c = n.namedChild(i); if (c && c.type === "simple_identifier") { name = c; break; } }
      if (name) fns.set(name.text, { params: kParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function kCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "call_expression") return null;
  const callee = kCallee(n);
  if (!callee || callee.type !== "simple_identifier") return null; // ローカル関数呼び出しのみ
  return { callee: callee.text, posArgs: kArgExprs(n) };
}
function kScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  kWalkScope(scope, (n) => {
    if (n.type !== "call_expression") return;
    const t = kCalleeText(n);
    const args = kArgExprs(n);
    const anyTainted = args.some((a) => kTainted(a, tainted));
    if ((t.endsWith(".exec") || t === "ProcessBuilder") && anyTainted) hit("taint.kotlin.command_injection", n);
    else if (K_SQL_SUFFIXES.some((s) => t.endsWith(s)) && anyTainted) hit("taint.kotlin.sql_injection", n);
    else if ((t === "File" || t.endsWith(".readText") || t.endsWith(".readBytes") || t.endsWith(".inputStream")) && anyTainted) hit("taint.kotlin.path_traversal", n);
    else if ((t === "URL" || t.endsWith(".get") || t.endsWith(".newCall")) && anyTainted && K_SOURCE_SUFFIXES.every((s) => !t.endsWith(s))) hit("taint.kotlin.ssrf", n);
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
    const rule = K_RULES[ruleId]; if (!rule) return;
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator: sha256(`${ruleId}:${node.text.slice(0, 80)}`) });
    if (seen.has(fingerprint)) return; seen.add(fingerprint);
    out.push({ schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id, cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: "likely", title: rule.title, message: rule.message, location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 }, snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint });
  };

  // taint: multi-level inter-procedural（共通エンジン）
  runInterProcTaint({
    root, moduleType: "source_file", scopeTypes: K_SCOPE_TYPES,
    collectFunctions: kCollectFunctions, collectTainted: kCollectTainted, scanSinks: kScanSinks,
    exprTainted: kTainted, callTarget: kCallTarget, walkScope: kWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

export async function initKotlin(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(KT_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["kt", "kts"]), detect, coveredRuleIds: new Set() });
}
