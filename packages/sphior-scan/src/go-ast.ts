/**
 * go-ast.ts — Go の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * Python 同様 pluggable backend として CLI/LSP が initGo() で登録する。
 * pattern（weak hash）＋ intra-procedural taint（command/SQL injection・SSRF・
 * path traversal）を Go AST で検出。engine core / Next には非依存。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { GO_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface GoRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const GO_RULES: Record<string, GoRule> = {
  "taint.go.command_injection": { id: "taint.go.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → exec.Command)", message: "Untrusted request input flows into exec.Command — OS command injection.", remediation: "Never pass untrusted input to a shell; validate/allowlist arguments.", references: REF("78") },
  "taint.go.sql_injection": { id: "taint.go.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → db query)", message: "Untrusted input is concatenated into a SQL query (Query/Exec).", remediation: "Use parameterized queries ($1 placeholders + args).", references: REF("89") },
  "taint.go.ssrf": { id: "taint.go.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → request URL)", message: "Untrusted input controls an outbound request URL (http.Get/NewRequest).", remediation: "Allowlist hosts/schemes; never fetch a URL built from input.", references: REF("918") },
  "taint.go.path_traversal": { id: "taint.go.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → file open)", message: "Untrusted input controls a filesystem path (os.Open/ReadFile).", remediation: "Clean+validate against an allowed base dir; reject '..'.", references: REF("22") },
  "pattern.go.weak_hash": { id: "pattern.go.weak_hash", cwe: "CWE-327", owasp: "A02:2021", severity: "medium", title: "Weak hash algorithm", message: "md5/sha1 are broken for security use.", remediation: "Use sha256+ or a password KDF (argon2/bcrypt/scrypt).", references: REF("327") },
};

// source: net/http・Gin・Echo・mux の untrusted 入力（call function.text の末尾一致）
const GO_SOURCE_CALL_SUFFIXES = [
  ".FormValue", ".PostFormValue", ".Query().Get", ".URL.Query().Get", ".Header.Get",
  ".Param", ".PostForm", ".DefaultQuery", ".QueryParam", ".Cookie", ".FormFile",
];
const GO_SCOPE_TYPES = new Set(["function_declaration", "method_declaration", "func_literal"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function goIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  if (node.type === "selector_expression" && node.text === "os.Args") return true;
  if (node.type === "call_expression") {
    const fn = node.childForFieldName("function");
    if (!fn) return false;
    const t = fn.text;
    return GO_SOURCE_CALL_SUFFIXES.some((s) => t.endsWith(s));
  }
  return false;
}

function goTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "identifier": return tainted.has(node.text);
    case "selector_expression":
      return goIsSource(node) || goTainted(node.childForFieldName("operand"), tainted);
    case "call_expression": {
      if (goIsSource(node)) return true;
      const fn = node.childForFieldName("function");
      // fmt.Sprintf(fmt, tainted...) は結果も汚染
      if (fn && fn.text === "fmt.Sprintf") {
        const args = node.childForFieldName("arguments");
        if (args) for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && goTainted(a, tainted)) return true; }
        return false;
      }
      // x.Method() は x が汚染なら汚染
      return !!fn && fn.type === "selector_expression" && goTainted(fn.childForFieldName("operand"), tainted);
    }
    case "binary_expression":
      return goTainted(node.childForFieldName("left"), tainted) || goTainted(node.childForFieldName("right"), tainted);
    case "parenthesized_expression":
    case "type_conversion_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && goTainted(c, tainted)) return true; }
      return false;
    }
    default:
      return goIsSource(node);
  }
}

function goWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && GO_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}

function goCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    goWalkScope(scope, (n) => {
      if (n.type === "short_var_declaration" || n.type === "assignment_statement") {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        if (!left || !right) return;
        const ln = left.namedChildCount, rn = right.namedChildCount;
        for (let i = 0; i < ln; i++) {
          const l = left.namedChild(i);
          const r = rn === ln ? right.namedChild(i) : right.namedChild(0);
          if (l && l.type === "identifier" && !tainted.has(l.text) && goTainted(r, tainted)) { tainted.add(l.text); changed = true; }
        }
      }
    });
  }
  return tainted;
}

/** call の第 i 引数（0-based・位置引数）。 */
function goArg(call: TsNode, i: number): TsNode | null {
  const args = call.childForFieldName("arguments");
  return args ? args.namedChild(i) : null;
}

// ── inter-procedural アダプタ ──
function goParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const pd = params.namedChild(i);
    if (!pd) continue;
    let hasName = false;
    for (let j = 0; j < pd.namedChildCount; j++) { const c = pd.namedChild(j); if (c && c.type === "identifier") { names.push(c.text); hasName = true; } }
    if (!hasName) names.push("");
  }
  return names;
}
function goCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "function_declaration" || n.type === "method_declaration") {
      const name = n.childForFieldName("name");
      if (name && (name.type === "identifier" || name.type === "field_identifier")) fns.set(name.text, { params: goParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function goCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "call_expression") return null;
  const fn = n.childForFieldName("function");
  if (!fn || fn.type !== "identifier") return null;
  const args = n.childForFieldName("arguments");
  const posArgs: (TsNode | null)[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) posArgs.push(args.namedChild(i));
  return { callee: fn.text, posArgs };
}
function goScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  goWalkScope(scope, (n) => {
    if (n.type !== "call_expression") return;
    const fn = n.childForFieldName("function");
    if (!fn) return;
    const t = fn.text;
    const field = fn.type === "selector_expression" ? (fn.childForFieldName("field")?.text ?? "") : "";
    const anyArgTainted = (): boolean => {
      const args = n.childForFieldName("arguments");
      if (!args) return false;
      for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && goTainted(a, tainted)) return true; }
      return false;
    };
    if ((t === "exec.Command" || t === "exec.CommandContext") && anyArgTainted()) hit("taint.go.command_injection", n);
    else if ((field === "Query" || field === "Exec" || field === "QueryRow" || field === "QueryContext" || field === "ExecContext" || field === "Prepare") && goTainted(goArg(n, 0), tainted)) hit("taint.go.sql_injection", n);
    else if ((t === "http.Get" || t === "http.Post" || t === "http.Head" || t === "http.PostForm") && goTainted(goArg(n, 0), tainted)) hit("taint.go.ssrf", n);
    else if (t === "http.NewRequest" && goTainted(goArg(n, 1), tainted)) hit("taint.go.ssrf", n);
    else if ((t === "os.Open" || t === "os.ReadFile" || t === "ioutil.ReadFile" || t === "os.Create" || t === "os.OpenFile") && goTainted(goArg(n, 0), tainted)) hit("taint.go.path_traversal", n);
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
    const rule = GO_RULES[ruleId];
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

  // pattern: weak hash（md5/sha1 の New/Sum）
  const walkPat = (n: TsNode): void => {
    if (n.type === "call_expression") {
      const fn = n.childForFieldName("function");
      const t = fn?.text ?? "";
      if (t === "md5.New" || t === "sha1.New" || t === "md5.Sum" || t === "sha1.Sum") add("pattern.go.weak_hash", n);
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) walkPat(c); }
  };
  walkPat(root);

  // taint: multi-level inter-procedural（共通エンジン）
  runInterProcTaint({
    root, moduleType: "source_file", scopeTypes: GO_SCOPE_TYPES,
    collectFunctions: goCollectFunctions, collectTainted: goCollectTainted, scanSinks: goScanSinks,
    exprTainted: goTainted, callTarget: goCallTarget, walkScope: goWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

/** tree-sitter Go を init し、engine にバックエンドを登録する。 */
export async function initGo(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(GO_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["go"]), detect, coveredRuleIds: new Set() });
}
