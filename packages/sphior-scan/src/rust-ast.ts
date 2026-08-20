/**
 * rust-ast.ts — Rust の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * source=env::args（CLI 引数）。intra-procedural taint（command injection・
 * path traversal・SSRF）を検出。Rust の型安全性ゆえ injection は少ないが、
 * Command/std::fs/reqwest への未検証入力は実脆弱性。go-ast と同型。
 */

import { loadParser } from "./tree-sitter-init";
import { runInterProcTaint, type Hit } from "./interproc";
import { RUST_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
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

interface RRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string; references: string[] }
const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const R_RULES: Record<string, RRule> = {
  "taint.rust.command_injection": { id: "taint.rust.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → Command)", message: "Untrusted input (env args) flows into std::process::Command args — command injection.", remediation: "Validate/allowlist arguments; avoid shell -c with input.", references: REF("78") },
  "taint.rust.path_traversal": { id: "taint.rust.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → fs)", message: "Untrusted input controls a filesystem path (std::fs/File).", remediation: "Canonicalize+validate against an allowed base dir.", references: REF("22") },
  "taint.rust.ssrf": { id: "taint.rust.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → request URL)", message: "Untrusted input controls an outbound URL (reqwest).", remediation: "Allowlist hosts/schemes.", references: REF("918") },
};

const R_SCOPE_TYPES = new Set(["function_item", "closure_expression"]);
const R_PATH_FNS = new Set(["fs::read", "fs::read_to_string", "fs::write", "File::open", "File::create", "fs::remove_file", "fs::read_dir"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

function rIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  if (node.type === "call_expression") {
    const fn = node.childForFieldName("function");
    return !!fn && fn.text.includes("env::args");
  }
  return false;
}
function rTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "identifier": return tainted.has(node.text);
    case "call_expression": {
      if (rIsSource(node)) return true;
      const fn = node.childForFieldName("function");
      return !!fn && fn.type === "field_expression" && rTainted(fn.childForFieldName("value"), tainted);
    }
    case "field_expression": return rTainted(node.childForFieldName("value"), tainted);
    case "index_expression": return rTainted(node.namedChild(0), tainted); // args[1] 等
    case "reference_expression": case "try_expression": case "parenthesized_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && rTainted(c, tainted)) return true; }
      return false;
    }
    case "macro_invocation": { // format!("{}", x)
      let f = false;
      const rec = (n: TsNode): void => { if (f) return; if (n.type === "identifier" && tainted.has(n.text)) { f = true; return; } for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); } };
      rec(node); return f;
    }
    default: return rIsSource(node);
  }
}
function rWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && R_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}
function rCollectTainted(scope: TsNode, seed: Iterable<string> = []): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    rWalkScope(scope, (n) => {
      if (n.type === "let_declaration") {
        const pat = n.childForFieldName("pattern");
        if (pat && pat.type === "identifier" && !tainted.has(pat.text) && rTainted(n.childForFieldName("value"), tainted)) { tainted.add(pat.text); changed = true; }
      } else if (n.type === "assignment_expression") {
        const left = n.childForFieldName("left");
        if (left && left.type === "identifier" && !tainted.has(left.text) && rTainted(n.childForFieldName("right"), tainted)) { tainted.add(left.text); changed = true; }
      }
    });
  }
  return tainted;
}
function rArg0(call: TsNode): TsNode | null {
  const args = call.childForFieldName("arguments");
  return args ? args.namedChild(0) : null;
}
function rAnyArg(call: TsNode, tainted: Set<string>): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  for (let i = 0; i < args.namedChildCount; i++) { const a = args.namedChild(i); if (a && rTainted(a, tainted)) return true; }
  return false;
}

// ── inter-procedural アダプタ ──
function rParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p || p.type !== "parameter") { names.push(""); continue; }
    const pat = p.childForFieldName("pattern");
    names.push(pat && pat.type === "identifier" ? pat.text : "");
  }
  return names;
}
function rCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "function_item") {
      const name = n.childForFieldName("name");
      if (name) fns.set(name.text, { params: rParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}
function rCallTarget(n: TsNode): { callee: string; posArgs: (TsNode | null)[] } | null {
  if (n.type !== "call_expression") return null;
  const fn = n.childForFieldName("function");
  if (!fn || fn.type !== "identifier") return null; // ローカル関数呼び出しのみ
  const args = n.childForFieldName("arguments");
  const posArgs: (TsNode | null)[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) posArgs.push(args.namedChild(i));
  return { callee: fn.text, posArgs };
}
function rScanSinks(scope: TsNode, tainted: Set<string>): Hit[] {
  const hits: Hit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  rWalkScope(scope, (n) => {
    if (n.type !== "call_expression") return;
    const fn = n.childForFieldName("function");
    const ft = fn?.text ?? "";
    if ((ft.endsWith(".arg") || ft.endsWith(".args") || ft.endsWith("Command::new")) && rAnyArg(n, tainted)) hit("taint.rust.command_injection", n);
    else if ([...R_PATH_FNS].some((f) => ft.endsWith(f)) && rTainted(rArg0(n), tainted)) hit("taint.rust.path_traversal", n);
    else if ((ft.endsWith("reqwest::get") || ft.endsWith("reqwest::blocking::get") || ft.endsWith("Client::get")) && rTainted(rArg0(n), tainted)) hit("taint.rust.ssrf", n);
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
    const rule = R_RULES[ruleId]; if (!rule) return;
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator: sha256(`${ruleId}:${node.text.slice(0, 80)}`) });
    if (seen.has(fingerprint)) return; seen.add(fingerprint);
    out.push({ schema_version: SCHEMA_VERSION, kind: "sast_pattern", rule_id: rule.id, cwe: rule.cwe, owasp: rule.owasp, severity: rule.severity, confidence: "likely", title: rule.title, message: rule.message, location: { path, start_line: node.startPosition.row + 1, start_col: node.startPosition.column + 1, end_line: node.endPosition.row + 1, end_col: node.endPosition.column + 1 }, snippet_hash: fingerprint, remediation: rule.remediation, references: rule.references, fingerprint });
  };

  // taint: multi-level inter-procedural（共通エンジン）
  runInterProcTaint({
    root, moduleType: "source_file", scopeTypes: R_SCOPE_TYPES,
    collectFunctions: rCollectFunctions, collectTainted: rCollectTainted, scanSinks: rScanSinks,
    exprTainted: rTainted, callTarget: rCallTarget, walkScope: rWalkScope,
  }, add);

  out.sort((a, b) => a.location.start_line !== b.location.start_line ? a.location.start_line - b.location.start_line : a.location.start_col - b.location.start_col);
  return out;
}

export async function initRust(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(RUST_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["rs"]), detect, coveredRuleIds: new Set() });
}
