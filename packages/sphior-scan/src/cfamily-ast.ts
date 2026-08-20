/**
 * cfamily-ast.ts — C / C++ の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * C 系固有の高シグナル脆弱性を multi-level inter-procedural taint で検出:
 *  - command injection (system/popen/exec*, std::system)         CWE-78
 *  - path traversal   (fopen/open/freopen/openat)                CWE-22
 *  - format string    (printf/fprintf/sprintf/snprintf/syslog)   CWE-134
 *  - buffer overflow  (strcpy/strcat/sprintf/stpcpy に汚染 src)  CWE-120
 * source = getenv() / argv / gets・fgets・scanf・read・recv 等の読取先バッファ。
 * C と C++ は tree-sitter-c 派生で節構造を共有するため detect を共通化し、
 * prefix（"c" / "cpp"）だけ差し替えて登録する。engine core / Next には非依存。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { C_GRAMMAR_WASM_B64, CPP_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface CFRule { cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const CF_RULE_DEFS: Record<string, CFRule> = {
  command_injection: { cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → system/exec)", message: "Untrusted input (env/argv/stdin) flows into system/popen/exec* — OS command injection.", remediation: "Avoid shell calls with input; use execve with a fixed binary + validated argv arrays." },
  path_traversal: { cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → file open)", message: "Untrusted input controls a filesystem path (fopen/open/freopen).", remediation: "Canonicalize (realpath) and validate against an allowed base dir; reject '..'." },
  format_string: { cwe: "CWE-134", owasp: "A03:2021", severity: "high", title: "Uncontrolled format string", message: "Untrusted input is used as a printf-family format argument — memory disclosure/corruption.", remediation: "Use a fixed format literal: printf(\"%s\", input), never printf(input)." },
  buffer_overflow: { cwe: "CWE-120", owasp: "A06:2021", severity: "high", title: "Buffer overflow (unbounded copy of untrusted input)", message: "Untrusted input is copied via strcpy/strcat/sprintf without bounds — buffer overflow.", remediation: "Use bounded variants (strncpy/strlcpy/snprintf) with explicit sizes." },
};

const CF_ENV_SOURCES = new Set(["getenv", "secure_getenv", "getenv_s"]);
// 読取先バッファを汚染する関数 → 汚染される引数位置（位置引数）
const CF_READ_DEST: Record<string, number[]> = {
  gets: [0], fgets: [0], fread: [0], read: [1], recv: [1], recvfrom: [1],
  scanf: [-1], sscanf: [-2], fscanf: [-1], // -1: format 後の全ポインタ, -2: format(第2)後の全ポインタ
};
const CF_CMD = new Set(["system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execvpe", "execvP"]);
const CF_PATH = new Set(["fopen", "freopen", "open", "openat", "open64", "fopen64", "_wfopen"]);
const CF_SCOPE_TYPES = new Set(["function_definition"]);

/** pointer_declarator/array_declarator 等を掘って最内の識別子を返す。 */
function cInnerIdent(node: TsNode | null): TsNode | null {
  if (!node) return null;
  if (node.type === "identifier" || node.type === "field_identifier" || node.type === "type_identifier") return node;
  const d = node.childForFieldName("declarator");
  if (d) return cInnerIdent(d);
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c && (c.type === "identifier" || c.type.endsWith("_declarator"))) { const r = cInnerIdent(c); if (r) return r; }
  }
  return null;
}
/** call の callee 名の最終セグメント（std::system→system / obj.exec→exec）。 */
function cCalleeName(fn: TsNode | null): string {
  if (!fn) return "";
  const t = fn.text;
  const seg = t.includes("::") ? t.slice(t.lastIndexOf("::") + 2) : t.includes(".") ? t.slice(t.lastIndexOf(".") + 1) : t;
  return seg;
}
function cArgList(call: TsNode): TsNode | null { return call.childForFieldName("arguments"); }
function cArg(call: TsNode, i: number): TsNode | null { const a = cArgList(call); return a ? a.namedChild(i) : null; }

export function makeCFamilyDetect(prefix: string): (path: string, text: string, parser: { parse(s: string): { rootNode: TsNode } }) => CanonicalFinding[] {
  const RULES: Record<string, CFRule & { id: string }> = {};
  for (const [k, v] of Object.entries(CF_RULE_DEFS)) RULES[`taint.${prefix}.${k}`] = { ...v, id: `taint.${prefix}.${k}` };
  const R = (k: string) => `taint.${prefix}.${k}`;

  function cIsSource(node: TsNode | null): boolean {
    if (!node) return false;
    if (node.type === "identifier") return node.text === "argv";
    if (node.type === "call_expression") return CF_ENV_SOURCES.has(cCalleeName(node.childForFieldName("function")));
    return false;
  }
  function cTainted(node: TsNode | null, tainted: Set<string>): boolean {
    if (!node) return false;
    switch (node.type) {
      case "identifier": return tainted.has(node.text) || node.text === "argv";
      case "call_expression": return cIsSource(node) || cTainted(node.childForFieldName("function"), tainted);
      case "field_expression": return cTainted(node.childForFieldName("argument") ?? node.namedChild(0), tainted);
      case "subscript_expression": return cTainted(node.childForFieldName("argument") ?? node.namedChild(0), tainted);
      case "pointer_expression": case "parenthesized_expression": case "cast_expression": {
        for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && cTainted(c, tainted)) return true; }
        return false;
      }
      case "binary_expression": return cTainted(node.childForFieldName("left"), tainted) || cTainted(node.childForFieldName("right"), tainted);
      default: return cIsSource(node);
    }
  }
  function cWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
    const rec = (n: TsNode, isRoot: boolean): void => {
      if (!isRoot && CF_SCOPE_TYPES.has(n.type)) return;
      visit(n);
      for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
    };
    rec(scope, true);
  }
  // read 系による汚染先バッファ名を収集
  function cReadDests(call: TsNode): string[] {
    const name = cCalleeName(call.childForFieldName("function"));
    const spec = CF_READ_DEST[name];
    if (!spec) return [];
    const args = cArgList(call);
    if (!args) return [];
    const out: string[] = [];
    const pushIdent = (e: TsNode | null): void => { const id = cInnerIdent(e); if (id) out.push(id.text); };
    if (spec[0] === -1) { for (let i = 1; i < args.namedChildCount; i++) pushIdent(args.namedChild(i)); }
    else if (spec[0] === -2) { for (let i = 2; i < args.namedChildCount; i++) pushIdent(args.namedChild(i)); }
    else for (const i of spec) pushIdent(args.namedChild(i));
    return out;
  }
  function cCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
    const tainted = new Set<string>(seed);
    let changed = true, guard = 0;
    while (changed && guard++ < 25) {
      changed = false;
      cWalkScope(scope, (n) => {
        if (n.type === "init_declarator") {
          const name = cInnerIdent(n.childForFieldName("declarator"));
          const value = n.childForFieldName("value");
          if (name && !tainted.has(name.text) && cTainted(value, tainted)) { tainted.add(name.text); changed = true; }
        } else if (n.type === "assignment_expression") {
          const left = cInnerIdent(n.childForFieldName("left"));
          if (left && !tainted.has(left.text) && cTainted(n.childForFieldName("right"), tainted)) { tainted.add(left.text); changed = true; }
        } else if (n.type === "call_expression") {
          for (const d of cReadDests(n)) if (!tainted.has(d)) { tainted.add(d); changed = true; }
        }
      });
    }
    return tainted;
  }
  function cAnyArg(call: TsNode, tainted: Set<string>): boolean {
    const args = cArgList(call);
    if (!args) return false;
    for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && cTainted(a, tainted)) return true; }
    return false;
  }
  // format 引数位置（printf=0 / fprintf=1 / sprintf=1 / snprintf=2 / syslog=1）
  const FMT_POS: Record<string, number> = { printf: 0, fprintf: 1, sprintf: 1, snprintf: 2, vsnprintf: 2, syslog: 1, vprintf: 0, vfprintf: 1 };
  // buffer overflow: 汚染 source 引数位置
  const BOF_SRC: Record<string, number[]> = { strcpy: [1], strcat: [1], stpcpy: [1], sprintf: [-1], vsprintf: [-1], gets: [0] };

  function cScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
    const hits: Hit[] = [];
    const hit = (k: string, node: TsNode): void => { hits.push({ ruleId: R(k), node }); };
    cWalkScope(scope, (n) => {
      if (n.type !== "call_expression") return;
      const name = cCalleeName(n.childForFieldName("function"));
      if (CF_CMD.has(name) && cAnyArg(n, tainted)) hit("command_injection", n);
      else if (CF_PATH.has(name) && cTainted(cArg(n, 0), tainted)) hit("path_traversal", n);
      // format string: format 位置の引数が汚染
      const fpos = FMT_POS[name];
      if (fpos !== undefined && cTainted(cArg(n, fpos), tainted)) hit("format_string", n);
      // buffer overflow: source 引数が汚染
      const bsrc = BOF_SRC[name];
      if (bsrc) {
        const args = cArgList(n);
        let tsrc = false;
        if (args) {
          if (bsrc[0] === -1) { for (let i = 1; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && cTainted(a, tainted)) { tsrc = true; break; } } }
          else for (const i of bsrc) { const a = args.namedChild(i); if (a && cTainted(a, tainted)) { tsrc = true; break; } }
        }
        if (tsrc) hit("buffer_overflow", n);
      }
    });
    return hits;
  }
  // inter-proc
  function cParamNames(fnDef: TsNode): string[] {
    const decl = fnDef.childForFieldName("declarator");
    // function_declarator を探す
    let fdecl: TsNode | null = decl;
    while (fdecl && fdecl.type !== "function_declarator") fdecl = fdecl.childForFieldName("declarator");
    const params = fdecl ? fdecl.childForFieldName("parameters") : null;
    const names: string[] = [];
    if (!params) return names;
    for (let i = 0; i < params.namedChildCount; i++) {
      const p = params.namedChild(i);
      if (!p || p.type !== "parameter_declaration") { names.push(""); continue; }
      const id = cInnerIdent(p.childForFieldName("declarator"));
      names.push(id ? id.text : "");
    }
    return names;
  }
  function cFnName(fnDef: TsNode): string {
    let fdecl: TsNode | null = fnDef.childForFieldName("declarator");
    while (fdecl && fdecl.type !== "function_declarator") fdecl = fdecl.childForFieldName("declarator");
    if (!fdecl) return "";
    const id = cInnerIdent(fdecl.childForFieldName("declarator"));
    return id ? id.text : "";
  }
  function cCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
    const fns = new Map<string, { params: string[]; scope: TsNode }>();
    const rec = (n: TsNode): void => {
      if (n.type === "function_definition") { const name = cFnName(n); if (name) fns.set(name, { params: cParamNames(n), scope: n }); }
      for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
    };
    rec(root);
    return fns;
  }
  function cCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
    if (n.type !== "call_expression") return null;
    const fn = n.childForFieldName("function");
    if (!fn || fn.type !== "identifier") return null; // ローカル関数呼び出しのみ
    const args = cArgList(n);
    const posArgs: (TsNode | null)[] = [];
    if (args) for (let i = 0; i < args.namedChildCount; i++) posArgs.push(args.namedChild(i));
    return { callee: fn.text, posArgs };
  }

  return (path: string, text: string, parser: { parse(s: string): { rootNode: TsNode } }): CanonicalFinding[] => {
    let root: TsNode;
    try { root = parser.parse(text).rootNode; } catch { return []; }
    const out: CanonicalFinding[] = [];
    const seen = new Set<string>();
    const add = (ruleId: string, node: TsNode): void => {
      const rule = RULES[ruleId]; if (!rule) return;
      const fingerprint = canonicalHash({ rule_id: ruleId, path, locator: sha256(`${ruleId}:${node.text.slice(0, 80)}`) });
      if (seen.has(fingerprint)) return; seen.add(fingerprint);
      out.push({ schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id, cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: "likely", title: rule.title, message: rule.message, location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 }, snippet_hash: fingerprint, remediation: rule.remediation, references: REF(rule.cwe.replace("CWE-", "")), fingerprint });
    };

    runInterProcTaint({
      root, moduleType: "translation_unit", scopeTypes: CF_SCOPE_TYPES,
      collectFunctions: cCollectFunctions, collectTainted: cCollectTainted, scanSinks: cScanSinks,
      exprTainted: cTainted, callTarget: cCallTarget, walkScope: cWalkScope,
    }, add);

    out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
    return out;
  };
}

let cParser: { parse(s: string): { rootNode: TsNode } } | null = null;
let cppParser: { parse(s: string): { rootNode: TsNode } } | null = null;
const cDetect = makeCFamilyDetect("c");
const cppDetect = makeCFamilyDetect("cpp");

/** tree-sitter C を init し、engine にバックエンドを登録する。 */
export async function initC(): Promise<void> {
  if (cParser) return;
  cParser = (await loadParser(C_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["c", "h"]), detect: (p, t) => cParser ? cDetect(p, t, cParser) : [], coveredRuleIds: new Set() });
}
/** tree-sitter C++ を init し、engine にバックエンドを登録する。 */
export async function initCpp(): Promise<void> {
  if (cppParser) return;
  cppParser = (await loadParser(CPP_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["cpp", "cc", "cxx", "hpp", "hh", "hxx"]), detect: (p, t) => cppParser ? cppDetect(p, t, cppParser) : [], coveredRuleIds: new Set() });
}
