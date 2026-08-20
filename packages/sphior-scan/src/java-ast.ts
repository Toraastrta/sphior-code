/**
 * java-ast.ts — Java の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * Servlet/Spring の request.getParameter 等を source に、intra-procedural taint
 * （command/SQL injection・SSRF・path traversal）＋ weak hash を検出。go/php-ast と同型。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { JAVA_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface JRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const J_RULES: Record<string, JRule> = {
  "taint.java.command_injection": { id: "taint.java.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → Runtime.exec/ProcessBuilder)", message: "Untrusted request input flows into Runtime.exec/ProcessBuilder — OS command injection.", remediation: "Use ProcessBuilder with a fixed command + validated args; never build shell strings.", references: REF("78") },
  "taint.java.sql_injection": { id: "taint.java.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → Statement)", message: "Untrusted input is concatenated into a SQL Statement (executeQuery/execute).", remediation: "Use PreparedStatement with bind parameters.", references: REF("89") },
  "taint.java.ssrf": { id: "taint.java.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → URL)", message: "Untrusted input controls an outbound URL (new URL / RestTemplate).", remediation: "Allowlist hosts/schemes.", references: REF("918") },
  "taint.java.path_traversal": { id: "taint.java.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → File)", message: "Untrusted input controls a filesystem path (new File / FileInputStream).", remediation: "Canonicalize+validate against an allowed base dir.", references: REF("22") },
  "pattern.java.weak_hash": { id: "pattern.java.weak_hash", cwe: "CWE-327", owasp: "A02:2021", severity: "medium", title: "Weak hash algorithm", message: "MessageDigest MD5/SHA-1 are broken for security use.", remediation: "Use SHA-256+ or a password KDF.", references: REF("327") },
};

const J_SOURCE_METHODS = new Set(["getParameter", "getParameterValues", "getParameterNames", "getHeader", "getHeaders", "getQueryString", "getParameterMap", "getRequestURI", "getCookies"]);
const J_SCOPE_TYPES = new Set(["method_declaration", "constructor_declaration", "lambda_expression"]);
const J_SQL = new Set(["executeQuery", "execute", "executeUpdate", "executeLargeUpdate", "prepareStatement", "prepareCall", "addBatch", "executeBatch"]);
const J_FILE_TYPES = new Set(["File", "FileInputStream", "FileReader", "RandomAccessFile", "FileOutputStream"]);

/**
 * 汚染を保存する良性変換メソッド（引数のいずれかが汚染なら結果も汚染）。
 * Benchmark を含む実コードは入力を decode/trim/substring 等に通してから sink に届けるため、
 * これを透過しないと大半の taint が変換で途切れる（本節の主因）。
 * 注意: サニタイザ（ESAPI encoder / StringEscapeUtils 等）は「汚染を除去」するので**含めない**。
 * これらは attacker 制御を保つ変換のみで、含めすぎると安全変種を FP にする（要 Benchmark 実測）。
 */
const J_PASSTHROUGH = new Set([
  "decode", "trim", "strip", "substring", "toString", "valueOf",
  "toUpperCase", "toLowerCase", "concat", "append", "format", "join", "intern", "toCharArray",
]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function jIsSource(node: TsNode | null): boolean {
  if (!node || node.type !== "method_invocation") return false;
  const name = node.childForFieldName("name")?.text ?? "";
  return J_SOURCE_METHODS.has(name);
}
function jTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "identifier": return tainted.has(node.text);
    case "method_invocation": {
      if (jIsSource(node)) return true;
      // 良性変換（decode/trim/getValue 等）は引数のいずれかが汚染なら結果も汚染とみなす。
      const nm = node.childForFieldName("name")?.text ?? "";
      if (J_PASSTHROUGH.has(nm) && jAnyArg(node, tainted)) return true;
      // 変換の receiver 側が汚染でも透過（param.toUpperCase() 等）。
      return jTainted(node.childForFieldName("object"), tainted);
    }
    case "binary_expression": return jTainted(node.childForFieldName("left"), tainted) || jTainted(node.childForFieldName("right"), tainted);
    case "parenthesized_expression": case "cast_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && jTainted(c, tainted)) return true; }
      return false;
    }
    default: return jIsSource(node);
  }
}
function jWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && J_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}
function jCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    jWalkScope(scope, (n) => {
      if (n.type === "variable_declarator") {
        const name = n.childForFieldName("name"); const value = n.childForFieldName("value");
        if (name && name.type === "identifier" && !tainted.has(name.text) && jTainted(value, tainted)) { tainted.add(name.text); changed = true; }
      } else if (n.type === "assignment_expression") {
        const left = n.childForFieldName("left");
        if (left && left.type === "identifier" && !tainted.has(left.text) && jTainted(n.childForFieldName("right"), tainted)) { tainted.add(left.text); changed = true; }
      }
    });
  }
  return tainted;
}
function jArg0(call: TsNode): TsNode | null {
  const args = call.childForFieldName("arguments");
  return args ? args.namedChild(0) : null;
}
function jAnyArg(call: TsNode, tainted: Set<string>): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && jTainted(a, tainted)) return true; }
  return false;
}

// ── inter-procedural アダプタ ──
function jParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p) { names.push(""); continue; }
    const nm = p.childForFieldName("name");
    names.push(nm && nm.type === "identifier" ? nm.text : "");
  }
  return names;
}
function jCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "method_declaration" || n.type === "constructor_declaration") {
      const name = n.childForFieldName("name");
      if (name) fns.set(name.text, { params: jParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function jCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "method_invocation") return null;
  if (n.childForFieldName("object")) return null; // ローカル(this)呼び出しのみ
  const name = n.childForFieldName("name");
  if (!name) return null;
  const args = n.childForFieldName("arguments");
  const posArgs: (TsNode | null)[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) posArgs.push(args.namedChild(i));
  return { callee: name.text, posArgs };
}
function jScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  jWalkScope(scope, (n) => {
    if (n.type === "method_invocation") {
      const name = n.childForFieldName("name")?.text ?? "";
      if (name === "exec" && jAnyArg(n, tainted)) hit("taint.java.command_injection", n);
      else if (J_SQL.has(name) && jTainted(jArg0(n), tainted)) hit("taint.java.sql_injection", n);
      else if ((name === "getForObject" || name === "getForEntity" || name === "exchange") && jAnyArg(n, tainted)) hit("taint.java.ssrf", n);
    } else if (n.type === "object_creation_expression") {
      const ty = n.childForFieldName("type")?.text ?? "";
      if (ty === "ProcessBuilder" && jAnyArg(n, tainted)) hit("taint.java.command_injection", n);
      else if (ty === "URL" && jTainted(jArg0(n), tainted)) hit("taint.java.ssrf", n);
      else if (J_FILE_TYPES.has(ty) && jTainted(jArg0(n), tainted)) hit("taint.java.path_traversal", n);
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
    const rule = J_RULES[ruleId]; if (!rule) return;
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator: sha256(`${ruleId}:${node.text.slice(0, 80)}`) });
    if (seen.has(fingerprint)) return; seen.add(fingerprint);
    out.push({ schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id, cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: ruleId.startsWith("taint.") ? "likely" : "confirmed", title: rule.title, message: rule.message, location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 }, snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint });
  };

  // pattern: weak hash MessageDigest.getInstance("MD5"/"SHA-1")
  const walkPat = (n: TsNode): void => {
    if (n.type === "method_invocation" && n.childForFieldName("name")?.text === "getInstance" && (n.childForFieldName("object")?.text ?? "").includes("MessageDigest")) {
      const a0 = jArg0(n)?.text ?? "";
      if (/["'](MD5|MD2|SHA-1|SHA1)["']/.test(a0)) add("pattern.java.weak_hash", n);
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) walkPat(c); }
  };
  walkPat(root);

  // taint: multi-level inter-procedural（共通エンジン）
  runInterProcTaint({
    root, moduleType: "program", scopeTypes: J_SCOPE_TYPES,
    collectFunctions: jCollectFunctions, collectTainted: jCollectTainted, scanSinks: jScanSinks,
    exprTainted: jTainted, callTarget: jCallTarget, walkScope: jWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

export async function initJava(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(JAVA_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["java"]), detect, coveredRuleIds: new Set() });
}
