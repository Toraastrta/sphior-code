/**
 * php-ast.ts — PHP の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * pattern（weak hash）＋ intra-procedural taint（command/code/SQL injection・
 * LFI・path traversal・XSS）を PHP AST で検出。source は superglobal（$_GET 等）。
 * engine core / Next には非依存。go-ast と同型。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { PHP_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface PhpRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const PHP_RULES: Record<string, PhpRule> = {
  "taint.php.command_injection": { id: "taint.php.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → system/exec)", message: "Untrusted request input flows into system/exec/shell_exec/passthru — OS command injection.", remediation: "Avoid shell calls; use escapeshellarg + validated allowlists.", references: REF("78") },
  "taint.php.code_injection": { id: "taint.php.code_injection", cwe: "CWE-95", owasp: "A03:2021", severity: "critical", title: "Code injection (untrusted input → eval)", message: "Untrusted input reaches eval()/assert()/create_function() — arbitrary code execution.", remediation: "Never eval untrusted input.", references: REF("95") },
  "taint.php.sql_injection": { id: "taint.php.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → query)", message: "Untrusted input is concatenated into a SQL query.", remediation: "Use prepared statements (PDO/mysqli bind params).", references: REF("89") },
  "taint.php.lfi": { id: "taint.php.lfi", cwe: "CWE-98", owasp: "A03:2021", severity: "critical", title: "File inclusion (untrusted input → include/require)", message: "Untrusted input controls an include/require target — LFI/RFI leading to code execution.", remediation: "Never include a path built from input; use an allowlist.", references: REF("98") },
  "taint.php.path_traversal": { id: "taint.php.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → file access)", message: "Untrusted input controls a filesystem path (fopen/file_get_contents).", remediation: "Validate against an allowed base dir; reject '..'.", references: REF("22") },
  "taint.php.xss": { id: "taint.php.xss", cwe: "CWE-79", owasp: "A03:2021", severity: "high", title: "XSS (untrusted input → echo/print)", message: "Untrusted input is echoed to the response without escaping.", remediation: "Escape with htmlspecialchars() before output.", references: REF("79") },
  "pattern.php.weak_hash": { id: "pattern.php.weak_hash", cwe: "CWE-327", owasp: "A02:2021", severity: "medium", title: "Weak hash algorithm", message: "md5()/sha1() are broken for security use.", remediation: "Use hash('sha256', …) or password_hash().", references: REF("327") },
};

const PHP_SUPERGLOBALS = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES"];
const PHP_SCOPE_TYPES = new Set(["function_definition", "method_declaration", "anonymous_function_creation_expression", "arrow_function"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function phpIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  if (node.type === "variable_name") return PHP_SUPERGLOBALS.includes(node.text);
  if (node.type === "subscript_expression") return PHP_SUPERGLOBALS.some((g) => node.text.startsWith(g));
  return false;
}

function phpTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "variable_name": return phpIsSource(node) || tainted.has(node.text);
    case "subscript_expression":
      return phpIsSource(node) || phpTainted(node.childForFieldName("object") ?? node.namedChild(0), tainted);
    case "binary_expression": // PHP の "." 連結
      return phpTainted(node.childForFieldName("left"), tainted) || phpTainted(node.childForFieldName("right"), tainted);
    case "encapsed_string":
    case "string": {
      // 補間中の変数
      let found = false;
      const rec = (n: TsNode): void => {
        if (found) return;
        if ((n.type === "variable_name" && (phpIsSource(n) || tainted.has(n.text))) || (n.type === "subscript_expression" && phpIsSource(n))) { found = true; return; }
        for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
      };
      rec(node);
      return found;
    }
    case "parenthesized_expression":
      return phpTainted(node.namedChild(0), tainted);
    default:
      return phpIsSource(node);
  }
}

function phpArg(call: TsNode, i: number): TsNode | null {
  const args = call.childForFieldName("arguments");
  if (!args) return null;
  const a = args.namedChild(i);
  if (!a) return null;
  return a.type === "argument" ? (a.namedChild(0) ?? a) : a;
}

function phpAnyArgTainted(call: TsNode, tainted: Set<string>): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  for (let i = 0; i < args.namedChildCount; i++) {
    const a = args.namedChild(i);
    const e = a && a.type === "argument" ? a.namedChild(0) : a;
    if (e && phpTainted(e, tainted)) return true;
  }
  return false;
}

function phpWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && PHP_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}

function phpCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    phpWalkScope(scope, (n) => {
      if (n.type === "assignment_expression") {
        const left = n.childForFieldName("left");
        if (left && left.type === "variable_name" && !tainted.has(left.text) && phpTainted(n.childForFieldName("right"), tainted)) {
          tainted.add(left.text); changed = true;
        }
      }
    });
  }
  return tainted;
}

const CMD_FUNCS = new Set(["system", "exec", "shell_exec", "passthru", "proc_open", "popen"]);
const CODE_FUNCS = new Set(["eval", "assert", "create_function"]);
const SQL_FUNCS = new Set(["mysqli_query", "mysql_query", "pg_query", "mysqli_multi_query"]);
const FILE_FUNCS = new Set(["fopen", "file_get_contents", "file", "readfile", "fpassthru"]);

// ── inter-procedural アダプタ ──
function phpParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p) continue;
    const vn = p.childForFieldName("name") ?? (() => { for (let j = 0; j < p.namedChildCount; j++) { const c = p.namedChild(j); if (c && c.type === "variable_name") return c; } return null; })();
    names.push(vn ? vn.text : "");
  }
  return names;
}
function phpCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "function_definition" || n.type === "method_declaration") {
      const name = n.childForFieldName("name");
      if (name) fns.set(name.text, { params: phpParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function phpCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "function_call_expression") return null;
  const fn = n.childForFieldName("function");
  if (!fn || (fn.type !== "name" && fn.type !== "qualified_name")) return null;
  const args = n.childForFieldName("arguments");
  const posArgs: (TsNode | null)[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); posArgs.push(a && a.type === "argument" ? (a.namedChild(0) ?? a) : a); }
  return { callee: fn.text, posArgs };
}
function phpScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  phpWalkScope(scope, (n) => {
    if (n.type === "function_call_expression") {
      const fn = n.childForFieldName("function");
      const name = fn?.text ?? "";
      if (CMD_FUNCS.has(name) && phpAnyArgTainted(n, tainted)) hit("taint.php.command_injection", n);
      else if (CODE_FUNCS.has(name) && phpAnyArgTainted(n, tainted)) hit("taint.php.code_injection", n);
      else if (SQL_FUNCS.has(name) && phpAnyArgTainted(n, tainted)) hit("taint.php.sql_injection", n);
      else if (FILE_FUNCS.has(name) && phpTainted(phpArg(n, 0), tainted)) hit("taint.php.path_traversal", n);
    } else if (n.type === "member_call_expression") {
      const method = n.childForFieldName("name")?.text ?? "";
      if ((method === "query" || method === "exec" || method === "unprepared") && phpAnyArgTainted(n, tainted)) hit("taint.php.sql_injection", n);
    } else if (n.type === "include_expression" || n.type === "require_expression") {
      const e = n.namedChild(0);
      if (e && phpTainted(e, tainted)) hit("taint.php.lfi", n);
    } else if (n.type === "echo_statement" || n.type === "print_intrinsic") {
      for (let i = 0; i < n.namedChildCount; i++) { const c = n.namedChild(i); if (c && phpTainted(c, tainted)) { hit("taint.php.xss", n); break; } }
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
    const rule = PHP_RULES[ruleId];
    if (!rule) return;
    const locator = sha256(`${ruleId}:${node.text.slice(0, 80)}`);
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator });
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    out.push({
      schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id,
      cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity,
      confidence: ruleId.startsWith("taint.") ? "likely" : "confirmed",
      title: rule.title, message: rule.message,
      location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 },
      snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint,
    });
  };

  // pattern: weak hash md5()/sha1()
  const walkPat = (n: TsNode): void => {
    if (n.type === "function_call_expression") {
      const fn = n.childForFieldName("function");
      if (fn && (fn.text === "md5" || fn.text === "sha1")) add("pattern.php.weak_hash", n);
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) walkPat(c); }
  };
  walkPat(root);

  // taint: multi-level inter-procedural（共通エンジン）
  runInterProcTaint({
    root, moduleType: "program", scopeTypes: PHP_SCOPE_TYPES,
    collectFunctions: phpCollectFunctions, collectTainted: phpCollectTainted, scanSinks: phpScanSinks,
    exprTainted: phpTainted, callTarget: phpCallTarget, walkScope: phpWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

/** tree-sitter PHP を init し、engine にバックエンドを登録する。 */
export async function initPhp(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(PHP_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["php"]), detect, coveredRuleIds: new Set() });
}
