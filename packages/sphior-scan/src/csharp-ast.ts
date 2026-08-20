/**
 * csharp-ast.ts — C# の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * ASP.NET の Request.Query/Form 等を source に、intra-procedural taint
 * （command/SQL injection・SSRF・path traversal・XSS）を検出。go/java-ast と同型。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { CS_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface CRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const C_RULES: Record<string, CRule> = {
  "taint.cs.command_injection": { id: "taint.cs.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → Process.Start)", message: "Untrusted request input flows into Process.Start — OS command injection.", remediation: "Never pass untrusted input to a shell; validate/allowlist arguments.", references: REF("78") },
  "taint.cs.sql_injection": { id: "taint.cs.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → SqlCommand)", message: "Untrusted input is concatenated into a SQL command.", remediation: "Use parameterized queries (SqlParameter).", references: REF("89") },
  "taint.cs.ssrf": { id: "taint.cs.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → request URL)", message: "Untrusted input controls an outbound request URL (WebClient/HttpClient).", remediation: "Allowlist hosts/schemes.", references: REF("918") },
  "taint.cs.path_traversal": { id: "taint.cs.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → file access)", message: "Untrusted input controls a filesystem path (File.ReadAllText/Open).", remediation: "Validate against an allowed base dir; reject '..'.", references: REF("22") },
  "taint.cs.xss": { id: "taint.cs.xss", cwe: "CWE-79", owasp: "A03:2021", severity: "high", title: "XSS (untrusted input → Response.Write)", message: "Untrusted input is written to the response without encoding.", remediation: "HTML-encode output (HttpUtility.HtmlEncode).", references: REF("79") },
};

const C_SOURCE_PREFIXES = ["Request.Query", "Request.Form", "Request.Params", "Request.QueryString", "Request.Headers", "Request.Cookies", "Request.RouteValues"];
const C_SCOPE_TYPES = new Set(["method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression"]);
const C_SQL_TYPES = new Set(["SqlCommand", "MySqlCommand", "NpgsqlCommand", "OracleCommand", "SQLiteCommand", "OleDbCommand"]);
const C_FILE_CALLS = new Set(["File.ReadAllText", "File.ReadAllBytes", "File.ReadAllLines", "File.OpenRead", "File.Open", "File.WriteAllText", "File.OpenText"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function csIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  if (node.type === "element_access_expression") {
    const e = node.childForFieldName("expression") ?? node.namedChild(0);
    return !!e && C_SOURCE_PREFIXES.some((p) => e.text === p || e.text.startsWith(`${p}.`));
  }
  if (node.type === "member_access_expression") return C_SOURCE_PREFIXES.some((p) => node.text === p || node.text.startsWith(`${p}.`));
  return false;
}
function csTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "identifier": return tainted.has(node.text);
    case "member_access_expression":
    case "element_access_expression":
      return csIsSource(node) || csTainted(node.childForFieldName("expression") ?? node.namedChild(0), tainted);
    case "invocation_expression": {
      const fn = node.childForFieldName("function");
      return !!fn && fn.type === "member_access_expression" && csTainted(fn.childForFieldName("expression") ?? fn.namedChild(0), tainted);
    }
    case "binary_expression": return csTainted(node.childForFieldName("left"), tainted) || csTainted(node.childForFieldName("right"), tainted);
    case "interpolated_string_expression": {
      let f = false;
      const rec = (n: TsNode): void => { if (f) return; if (n.type === "interpolation") { for (let i = 0; i < n.namedChildCount; i++) { const c = n.namedChild(i); if (c && csTainted(c, tainted)) { f = true; return; } } } for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); } };
      rec(node); return f;
    }
    case "parenthesized_expression": case "cast_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && csTainted(c, tainted)) return true; }
      return false;
    }
    default: return csIsSource(node);
  }
}
function csWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && C_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}
function csVarValue(decl: TsNode): TsNode | null {
  for (let i = 0; i < decl.childCount; i++) { const c = decl.child(i); if (c && c.type === "equals_value_clause") return c.namedChild(0); }
  return null;
}
function csCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    csWalkScope(scope, (n) => {
      if (n.type === "variable_declarator") {
        const name = n.childForFieldName("name") ?? n.namedChild(0);
        if (name && name.type === "identifier" && !tainted.has(name.text) && csTainted(csVarValue(n), tainted)) { tainted.add(name.text); changed = true; }
      } else if (n.type === "assignment_expression") {
        const left = n.childForFieldName("left");
        if (left && left.type === "identifier" && !tainted.has(left.text) && csTainted(n.childForFieldName("right"), tainted)) { tainted.add(left.text); changed = true; }
      }
    });
  }
  return tainted;
}
function csArg0(call: TsNode): TsNode | null {
  const args = call.childForFieldName("arguments");
  if (!args) return null;
  const a = args.namedChild(0);
  return a && a.type === "argument" ? (a.namedChild(0) ?? a) : a;
}
function csAnyArg(call: TsNode, tainted: Set<string>): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); const e = a && a.type === "argument" ? a.namedChild(0) : a; if (e && csTainted(e, tainted)) return true; }
  return false;
}

// ── inter-procedural アダプタ ──
function csParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p || p.type !== "parameter") { names.push(""); continue; }
    const nm = p.childForFieldName("name");
    names.push(nm && nm.type === "identifier" ? nm.text : "");
  }
  return names;
}
function csCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "method_declaration" || n.type === "local_function_statement" || n.type === "constructor_declaration") {
      const name = n.childForFieldName("name");
      if (name) fns.set(name.text, { params: csParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function csCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "invocation_expression") return null;
  const fn = n.childForFieldName("function");
  if (!fn || fn.type !== "identifier") return null; // ローカル呼び出しのみ
  const args = n.childForFieldName("arguments");
  const posArgs: (TsNode | null)[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); posArgs.push(a && a.type === "argument" ? (a.namedChild(0) ?? a) : a); }
  return { callee: fn.text, posArgs };
}
function csScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  csWalkScope(scope, (n) => {
    if (n.type === "invocation_expression") {
      const ft = n.childForFieldName("function")?.text ?? "";
      if ((ft === "Process.Start" || ft.endsWith(".Start")) && ft.includes("Process") && csAnyArg(n, tainted)) hit("taint.cs.command_injection", n);
      else if (C_FILE_CALLS.has(ft) && csTainted(csArg0(n), tainted)) hit("taint.cs.path_traversal", n);
      else if ((ft.endsWith(".DownloadString") || ft.endsWith(".DownloadData") || ft.endsWith(".GetStringAsync") || ft.endsWith(".GetAsync") || ft.endsWith(".OpenRead")) && csTainted(csArg0(n), tainted)) hit("taint.cs.ssrf", n);
      else if ((ft === "Response.Write" || ft.endsWith(".Response.Write")) && csAnyArg(n, tainted)) hit("taint.cs.xss", n);
    } else if (n.type === "object_creation_expression") {
      const ty = n.childForFieldName("type")?.text ?? "";
      if (C_SQL_TYPES.has(ty) && csTainted(csArg0(n), tainted)) hit("taint.cs.sql_injection", n);
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
    const rule = C_RULES[ruleId]; if (!rule) return;
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator: sha256(`${ruleId}:${node.text.slice(0, 80)}`) });
    if (seen.has(fingerprint)) return; seen.add(fingerprint);
    out.push({ schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id, cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: "likely", title: rule.title, message: rule.message, location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 }, snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint });
  };

  // taint: multi-level inter-procedural（共通エンジン）
  runInterProcTaint({
    root, moduleType: "compilation_unit", scopeTypes: C_SCOPE_TYPES,
    collectFunctions: csCollectFunctions, collectTainted: csCollectTainted, scanSinks: csScanSinks,
    exprTainted: csTainted, callTarget: csCallTarget, walkScope: csWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

export async function initCsharp(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(CS_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["cs"]), detect, coveredRuleIds: new Set() });
}
