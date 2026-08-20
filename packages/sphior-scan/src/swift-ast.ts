/**
 * swift-ast.ts — Swift の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * server-side Swift（Vapor）/ CLI。source = CommandLine.arguments /
 * ProcessInfo.environment / URLComponents.queryItems / request.value。
 * multi-level inter-procedural taint（command injection・path traversal・SSRF）。
 * Swift の call は call_suffix→value_arguments 経由（kotlin-ast と同型）。
 * engine core / Next には非依存。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { SWIFT_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface WRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const W_RULES: Record<string, WRule> = {
  "taint.swift.command_injection": { id: "taint.swift.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → Process/system)", message: "Untrusted input (argv/env/request) flows into Process/system — OS command injection.", remediation: "Set a fixed executableURL and pass validated arguments arrays; never invoke a shell with input.", references: REF("78") },
  "taint.swift.path_traversal": { id: "taint.swift.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → file access)", message: "Untrusted input controls a filesystem path (contentsOfFile/contentsOf).", remediation: "Validate against an allowed base dir; reject '..'.", references: REF("22") },
  "taint.swift.ssrf": { id: "taint.swift.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → request URL)", message: "Untrusted input controls an outbound URL (URL(string:)/dataTask).", remediation: "Allowlist hosts/schemes.", references: REF("918") },
};

const W_SOURCE_SUBSTR = ["CommandLine.arguments", ".environment[", ".queryItems", "forHTTPHeaderField", "readLine(", ".queryParameters", "request.body"];
const W_SCOPE_TYPES = new Set(["function_declaration", "lambda_literal"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function wCallee(call: TsNode): TsNode | null { return call.namedChild(0); }
function wCalleeText(call: TsNode): string { return wCallee(call)?.text ?? ""; }
/** call_suffix→value_arguments の各実引数式を返す。 */
function wArgExprs(call: TsNode): TsNode[] {
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

function wIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  const t = node.text;
  return W_SOURCE_SUBSTR.some((s) => t.includes(s));
}
function wTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  if (wIsSource(node)) return true;
  switch (node.type) {
    case "simple_identifier": return tainted.has(node.text);
    case "call_expression": return wTainted(wCallee(node), tainted);
    case "navigation_expression": return wTainted(node.namedChild(0), tainted);
    case "additive_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && wTainted(c, tainted)) return true; }
      return false;
    }
    case "line_string_literal": {
      let f = false;
      const rec = (n: TsNode): void => { if (f) return; if (n.type === "simple_identifier" && tainted.has(n.text)) { f = true; return; } for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); } };
      rec(node); return f;
    }
    default: return false;
  }
}
function wWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && W_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}
/** property_declaration の束縛名（pattern 内の simple_identifier）。 */
function wBindName(decl: TsNode): TsNode | null {
  for (let i = 0; i < decl.namedChildCount; i++) {
    const c = decl.namedChild(i);
    if (!c) continue;
    if (c.type === "pattern") { for (let j = 0; j < c.namedChildCount; j++) { const g = c.namedChild(j); if (g && g.type === "simple_identifier") return g; } }
    if (c.type === "simple_identifier") return c;
  }
  return null;
}
function wBindValue(decl: TsNode): TsNode | null {
  let value: TsNode | null = null;
  for (let i = 0; i < decl.namedChildCount; i++) {
    const c = decl.namedChild(i);
    if (c && c.type !== "value_binding_pattern" && c.type !== "pattern" && c.type !== "type_annotation" && c.type !== "modifiers") value = c;
  }
  return value;
}
function wCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    wWalkScope(scope, (n) => {
      if (n.type === "property_declaration") {
        const name = wBindName(n); const value = wBindValue(n);
        if (name && !tainted.has(name.text) && wTainted(value, tainted)) { tainted.add(name.text); changed = true; }
      } else if (n.type === "assignment") {
        const left = n.namedChild(0); const right = n.namedChild(n.namedChildCount - 1);
        if (left && left.type === "simple_identifier" && !tainted.has(left.text) && wTainted(right, tainted)) { tainted.add(left.text); changed = true; }
      }
    });
  }
  return tainted;
}

// ── inter-procedural アダプタ ──
function wParamNames(fnDef: TsNode): string[] {
  const names: string[] = [];
  for (let i = 0; i < fnDef.namedChildCount; i++) {
    const p = fnDef.namedChild(i);
    if (!p || p.type !== "parameter") continue;
    let last: TsNode | null = null;
    for (let j = 0; j < p.namedChildCount; j++) { const c = p.namedChild(j); if (c && c.type === "simple_identifier") last = c; }
    names.push(last ? last.text : "");
  }
  return names;
}
function wCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "function_declaration") {
      let name: TsNode | null = null;
      for (let i = 0; i < n.namedChildCount; i++) { const c = n.namedChild(i); if (c && c.type === "simple_identifier") { name = c; break; } }
      if (name) fns.set(name.text, { params: wParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function wCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "call_expression") return null;
  const callee = wCallee(n);
  if (!callee || callee.type !== "simple_identifier") return null; // ローカル関数呼び出しのみ
  return { callee: callee.text, posArgs: wArgExprs(n) };
}
function wScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  wWalkScope(scope, (n) => {
    if (n.type === "call_expression") {
      const t = wCalleeText(n);
      const args = wArgExprs(n);
      const anyTainted = args.some((a) => wTainted(a, tainted));
      if ((t === "system" || t === "Process" || t.endsWith(".run") || t.endsWith(".launch")) && anyTainted) hit("taint.swift.command_injection", n);
      else if ((t === "String" || t === "Data" || t === "NSData" || t.endsWith(".contentsOfFile") || t.endsWith("contentsOf") || t.endsWith(".contents")) && args.some((a) => wTainted(a, tainted))) hit("taint.swift.path_traversal", n);
      else if ((t === "URL" || t === "URLRequest" || t.endsWith(".dataTask") || t.endsWith(".data")) && anyTainted) hit("taint.swift.ssrf", n);
    } else if (n.type === "assignment") {
      // process.launchPath = tainted / process.arguments = tainted
      const left = n.namedChild(0);
      if (left && (left.text.endsWith(".launchPath") || left.text.endsWith(".arguments") || left.text.endsWith(".executableURL"))) {
        const right = n.namedChild(n.namedChildCount - 1);
        if (right && wTainted(right, tainted)) hit("taint.swift.command_injection", n);
      }
    }
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
    const rule = W_RULES[ruleId]; if (!rule) return;
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator: sha256(`${ruleId}:${node.text.slice(0, 80)}`) });
    if (seen.has(fingerprint)) return; seen.add(fingerprint);
    out.push({ schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id, cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: "likely", title: rule.title, message: rule.message, location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 }, snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint });
  };

  runInterProcTaint({
    root, moduleType: "source_file", scopeTypes: W_SCOPE_TYPES,
    collectFunctions: wCollectFunctions, collectTainted: wCollectTainted, scanSinks: wScanSinks,
    exprTainted: wTainted, callTarget: wCallTarget, walkScope: wWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

export async function initSwift(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(SWIFT_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["swift"]), detect, coveredRuleIds: new Set() });
}
