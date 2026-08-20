/**
 * ruby-ast.ts — Ruby の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * intra-procedural taint（command/code/SQL injection・SSRF・path traversal・XSS）。
 * source は Rails の params/cookies/session。go/php-ast と同型。call と command
 * (括弧なし呼び出し)の両方を扱う。engine core / Next には非依存。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { RB_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
import { registerAstBackend } from "./engine/patterns/ast-backend";
import type { CanonicalFinding, Severity } from "./engine/types";
import { SCHEMA_VERSION } from "./engine/types";
import { sha256, canonicalHash } from "./engine/canonical";

interface TsNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  childCount: number;
  child(i: number): TsNode | null;
  namedChildCount: number;
  namedChild(i: number): TsNode | null;
  childForFieldName(name: string): TsNode | null;
}

interface RbRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const RB_RULES: Record<string, RbRule> = {
  "taint.rb.command_injection": { id: "taint.rb.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → system/exec)", message: "Untrusted params flow into system/exec/spawn — OS command injection.", remediation: "Avoid shell calls with input; use system([...]) array form + allowlists.", references: REF("78") },
  "taint.rb.code_injection": { id: "taint.rb.code_injection", cwe: "CWE-95", owasp: "A03:2021", severity: "critical", title: "Code injection (untrusted input → eval)", message: "Untrusted params reach eval/instance_eval/class_eval — arbitrary code execution.", remediation: "Never eval untrusted input.", references: REF("95") },
  "taint.rb.sql_injection": { id: "taint.rb.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → query)", message: "Untrusted input is interpolated into a query (where/find_by_sql/execute).", remediation: "Use parameterized queries (where('x = ?', v)).", references: REF("89") },
  "taint.rb.ssrf": { id: "taint.rb.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → request URL)", message: "Untrusted params control an outbound request URL (Net::HTTP/HTTParty).", remediation: "Allowlist hosts/schemes.", references: REF("918") },
  "taint.rb.path_traversal": { id: "taint.rb.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → file access)", message: "Untrusted params control a filesystem path (File.read/open).", remediation: "Validate against an allowed base dir; reject '..'.", references: REF("22") },
  "taint.rb.xss": { id: "taint.rb.xss", cwe: "CWE-79", owasp: "A03:2021", severity: "high", title: "XSS (untrusted input → raw/html_safe)", message: "Untrusted params are marked html_safe / raw without escaping.", remediation: "Never html_safe user input; rely on Rails auto-escaping.", references: REF("79") },
};

const RB_SOURCE_OBJECTS = new Set(["params", "cookies", "session"]);
const RB_SOURCE_METHODS = new Set(["params", "query_parameters", "request_parameters", "GET", "POST"]);
const RB_SCOPE_TYPES = new Set(["method", "singleton_method"]);
const RB_CALL_TYPES = new Set(["call", "command", "command_call", "method_call"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function rbIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  if (node.type === "element_reference") {
    const obj = node.namedChild(0);
    return !!obj && obj.type === "identifier" && RB_SOURCE_OBJECTS.has(obj.text);
  }
  if (RB_CALL_TYPES.has(node.type)) {
    const m = node.childForFieldName("method");
    return !!m && RB_SOURCE_METHODS.has(m.text);
  }
  return false;
}

function rbTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "identifier": return tainted.has(node.text);
    case "element_reference":
      return rbIsSource(node) || rbTainted(node.namedChild(0), tainted);
    case "binary":
      return rbTainted(node.childForFieldName("left"), tainted) || rbTainted(node.childForFieldName("right"), tainted);
    case "string":
    case "string_content": {
      let found = false;
      const rec = (n: TsNode): void => {
        if (found) return;
        if (n.type === "interpolation") { for (let i = 0; i < n.namedChildCount; i++) { const c = n.namedChild(i); if (c && rbTainted(c, tainted)) { found = true; return; } } }
        for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
      };
      rec(node);
      return found;
    }
    case "parenthesized_statements":
      return rbTainted(node.namedChild(0), tainted);
    default:
      if (RB_CALL_TYPES.has(node.type)) {
        if (rbIsSource(node)) return true;
        return rbTainted(node.childForFieldName("receiver"), tainted); // x.strip 等
      }
      return rbIsSource(node);
  }
}

function rbWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && RB_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}

function rbCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    rbWalkScope(scope, (n) => {
      if (n.type === "assignment") {
        const left = n.childForFieldName("left");
        if (left && left.type === "identifier" && !tainted.has(left.text) && rbTainted(n.childForFieldName("right"), tainted)) {
          tainted.add(left.text); changed = true;
        }
      }
    });
  }
  return tainted;
}

function rbArg(call: TsNode, i: number): TsNode | null {
  const args = call.childForFieldName("arguments");
  return args ? args.namedChild(i) : null;
}
function rbAnyArgTainted(call: TsNode, tainted: Set<string>): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && rbTainted(a, tainted)) return true; }
  return false;
}

const RB_CMD = new Set(["system", "exec", "spawn", "syscall"]);
const RB_CODE = new Set(["eval", "instance_eval", "class_eval", "module_eval"]);
const RB_SQL = new Set(["where", "find_by_sql", "exec_query", "execute", "select_all", "select_rows", "select_values"]);
const RB_HTTP_RECV = new Set(["Net::HTTP", "HTTParty", "RestClient", "Faraday", "Excon"]);
const RB_FILE_RECV = new Set(["File", "IO"]);

// ── inter-procedural アダプタ ──
function rbParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p) { names.push(""); continue; }
    if (p.type === "identifier") names.push(p.text);
    else { const id = p.childForFieldName("name") ?? p.namedChild(0); names.push(id && id.type === "identifier" ? id.text : ""); }
  }
  return names;
}
function rbCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "method" || n.type === "singleton_method") {
      const name = n.childForFieldName("name");
      if (name) fns.set(name.text, { params: rbParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function rbCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (!RB_CALL_TYPES.has(n.type)) return null;
  if (n.childForFieldName("receiver")) return null; // ローカル呼び出しのみ
  const m = n.childForFieldName("method");
  if (!m) return null;
  const args = n.childForFieldName("arguments");
  const posArgs: (TsNode | null)[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) posArgs.push(args.namedChild(i));
  return { callee: m.text, posArgs };
}
function rbScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  rbWalkScope(scope, (n) => {
    if (!RB_CALL_TYPES.has(n.type)) return;
    const method = n.childForFieldName("method")?.text ?? "";
    const recv = n.childForFieldName("receiver")?.text ?? null;
    if (RB_CMD.has(method) && !recv && rbAnyArgTainted(n, tainted)) hit("taint.rb.command_injection", n);
    else if (RB_CODE.has(method) && rbAnyArgTainted(n, tainted)) hit("taint.rb.code_injection", n);
    else if (RB_SQL.has(method) && rbTainted(rbArg(n, 0), tainted)) hit("taint.rb.sql_injection", n);
    else if ((method === "get" || method === "post" || method === "get_response") && !!recv && RB_HTTP_RECV.has(recv) && rbTainted(rbArg(n, 0), tainted)) hit("taint.rb.ssrf", n);
    else if (((!!recv && RB_FILE_RECV.has(recv) && ["read", "open", "new", "readlines", "binread", "write"].includes(method)) || (!recv && method === "open")) && rbTainted(rbArg(n, 0), tainted)) hit("taint.rb.path_traversal", n);
    else if ((method === "raw" && rbAnyArgTainted(n, tainted)) || (method === "html_safe" && rbTainted(n.childForFieldName("receiver"), tainted))) hit("taint.rb.xss", n);
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
    const rule = RB_RULES[ruleId];
    if (!rule) return;
    const locator = sha256(`${ruleId}:${node.text.slice(0, 80)}`);
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator });
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    out.push({
      schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id,
      cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: "likely",
      title: rule.title, message: rule.message,
      location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 },
      snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint,
    });
  };

  // taint: multi-level inter-procedural（共通エンジン）
  runInterProcTaint({
    root, moduleType: "program", scopeTypes: RB_SCOPE_TYPES,
    collectFunctions: rbCollectFunctions, collectTainted: rbCollectTainted, scanSinks: rbScanSinks,
    exprTainted: rbTainted, callTarget: rbCallTarget, walkScope: rbWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

/** tree-sitter Ruby を init し、engine にバックエンドを登録する。 */
export async function initRuby(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(RB_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["rb"]), detect, coveredRuleIds: new Set() });
}
