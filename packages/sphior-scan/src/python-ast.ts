/**
 * python-ast.ts — Python の tree-sitter AST バックエンド（@sphior/scan 専用）
 *
 * engine core / Next には持ち込まない（本番ビルド無風）。CLI/LSP が起動時に
 * `initPython()` を呼ぶと tree-sitter を init し、engine の pluggable レジストリへ
 * バックエンドを登録する。以降 .py は AST で高精度検出（文字列/コメント内の
 * 擬似マッチを排除）。未 init 環境では engine は regex にフォールバックする。
 *
 * WASM は base64 で同梱（gen-wasm.mjs）→ 実行時のファイル解決不要・自己完結。
 */

import { loadParser } from "./tree-sitter-init";
import { PY_GRAMMAR_WASM_B64 } from "./gen/wasm-blobs";
import { registerAstBackend } from "./engine/patterns/ast-backend";
import type { CanonicalFinding, Severity } from "./engine/types";
import { SCHEMA_VERSION } from "./engine/types";
import { sha256, canonicalHash } from "./engine/canonical";
import { PATTERN_RULES } from "./engine/patterns/rules";

// ── tree-sitter の最小ノード型（web-tree-sitter の実体を薄く受ける） ──
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

const RULE_BY_ID = new Map(PATTERN_RULES.map((r) => [r.id, r]));
const COVERED = new Set(["pattern.py.eval", "pattern.py.exec", "pattern.py.os_system", "pattern.py.subprocess_shell_true"]);

let parser: { parse(s: string): { rootNode: TsNode } } | null = null;

// ── Python taint（source→sink・intra-procedural）──────────────────────────────
interface PyTaintRule { id: string; cwe: string; owasp: string; severity: Severity; title: string; message: string; remediation: string }
const PY_REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];
const PY_TAINT_RULES: Record<string, PyTaintRule & { references: string[] }> = {
  "taint.py.command_injection": { id: "taint.py.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical", title: "Command injection (untrusted input → shell)", message: "Untrusted request input flows into a shell command (os.system/popen/subprocess shell=True).", remediation: "Use subprocess.run([...], shell=False); never build shell strings from input.", references: PY_REF("78") },
  "taint.py.code_injection": { id: "taint.py.code_injection", cwe: "CWE-95", owasp: "A03:2021", severity: "critical", title: "Code injection (untrusted input → eval/exec)", message: "Untrusted request input flows into eval()/exec() — arbitrary code execution.", remediation: "Never eval/exec untrusted input; use explicit logic.", references: PY_REF("95") },
  "taint.py.sql_injection": { id: "taint.py.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical", title: "SQL injection (untrusted input → query)", message: "Untrusted input is interpolated into a SQL query (cursor.execute/raw).", remediation: "Use parameterized queries (execute(sql, params)).", references: PY_REF("89") },
  "taint.py.ssrf": { id: "taint.py.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high", title: "SSRF (untrusted input → request URL)", message: "Untrusted input controls an outbound request URL (requests/urllib).", remediation: "Allowlist hosts/schemes; never fetch a URL built from input.", references: PY_REF("918") },
  "taint.py.path_traversal": { id: "taint.py.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high", title: "Path traversal (untrusted input → open)", message: "Untrusted input controls a filesystem path (open) — path traversal.", remediation: "Resolve/validate against an allowed base dir; reject '..'.", references: PY_REF("22") },
  "taint.py.ssti": { id: "taint.py.ssti", cwe: "CWE-94", owasp: "A03:2021", severity: "critical", title: "Template injection (untrusted input → render_template_string)", message: "Untrusted input reaches render_template_string() — Jinja2 SSTI.", remediation: "Render fixed templates with a context; never build the template from input.", references: PY_REF("94") },
  "taint.py.deserialization": { id: "taint.py.deserialization", cwe: "CWE-502", owasp: "A08:2021", severity: "critical", title: "Unsafe deserialization (untrusted input → pickle/yaml)", message: "Untrusted input is deserialized (pickle.load/loads or yaml.load) — remote code execution.", remediation: "Never unpickle untrusted data; use JSON or yaml.safe_load.", references: PY_REF("502") },
  "taint.py.xss": { id: "taint.py.xss", cwe: "CWE-79", owasp: "A03:2021", severity: "high", title: "XSS (untrusted input → response)", message: "Untrusted input is returned in a raw HttpResponse/Response/make_response without escaping.", remediation: "Escape output; use template auto-escaping (never mark_safe user data).", references: PY_REF("79") },
  "taint.py.nosql_injection": { id: "taint.py.nosql_injection", cwe: "CWE-943", owasp: "A03:2021", severity: "high", title: "NoSQL injection (untrusted object → Mongo query)", message: "An untrusted object is passed to a MongoDB query (find_one/update_one/aggregate).", remediation: "Validate/whitelist fields; never pass request data directly as a filter.", references: PY_REF("943") },
  "taint.py.xxe": { id: "taint.py.xxe", cwe: "CWE-611", owasp: "A05:2021", severity: "high", title: "XXE (untrusted XML → parser)", message: "Untrusted XML is parsed (etree/minidom/sax) — XML external entity injection.", remediation: "Use defusedxml, or disable external entities (resolve_entities=False).", references: PY_REF("611") },
  "taint.py.xpath_injection": { id: "taint.py.xpath_injection", cwe: "CWE-643", owasp: "A03:2021", severity: "high", title: "XPath injection (untrusted input → xpath)", message: "Untrusted input is used in an XPath query (.xpath).", remediation: "Use parameterized XPath (lxml variables) or validate/escape input.", references: PY_REF("643") },
  "taint.py.ldap_injection": { id: "taint.py.ldap_injection", cwe: "CWE-90", owasp: "A03:2021", severity: "high", title: "LDAP injection (untrusted input → filter)", message: "Untrusted input is used in an LDAP filter (search_s).", remediation: "Escape LDAP special chars (ldap.filter.escape_filter_chars).", references: PY_REF("90") },
};
const PY_XML_PARSE = ["etree.parse", "etree.fromstring", "etree.XML", "minidom.parse", "minidom.parseString", "sax.parse", "sax.parseString", "ElementTree.parse", "ElementTree.fromstring", "pulldom.parse"];
const PY_MONGO_METHODS = ["find_one", "find_one_and_update", "find_one_and_delete", "update_one", "update_many", "delete_one", "delete_many", "aggregate", "count_documents", "insert_one", "replace_one"];

const PY_SOURCE_PREFIXES = [
  "request.args", "request.form", "request.values", "request.json", "request.data",
  "request.cookies", "request.headers", "request.files",
  "request.GET", "request.POST", "request.body",
];
const PY_SCOPE_TYPES = new Set(["function_definition", "lambda"]);

function pyIsSource(node: TsNode | null): boolean {
  if (!node) return false;
  if (node.type === "attribute" || node.type === "subscript" || node.type === "identifier") {
    const t = node.text;
    return PY_SOURCE_PREFIXES.some((p) => t === p || t.startsWith(`${p}.`) || t.startsWith(`${p}[`));
  }
  if (node.type === "call") {
    const fn = node.childForFieldName("function");
    if (!fn) return false;
    if (fn.type === "identifier" && fn.text === "input") return true;
    const t = fn.text;
    return t === "request.get_json" || PY_SOURCE_PREFIXES.some((p) => t.startsWith(`${p}.`));
  }
  return false;
}

/** string(f-string) の補間に汚染が含まれるか。 */
function pyStringHasTaint(node: TsNode, tainted: Set<string>): boolean {
  let found = false;
  const rec = (n: TsNode): void => {
    if (found) return;
    if (n.type === "identifier" && tainted.has(n.text)) { found = true; return; }
    if ((n.type === "attribute" || n.type === "subscript" || n.type === "call") && pyIsSource(n)) { found = true; return; }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(node);
  return found;
}

function pyTainted(node: TsNode | null, tainted: Set<string>): boolean {
  if (!node) return false;
  switch (node.type) {
    case "identifier": return tainted.has(node.text);
    case "attribute":
    case "subscript":
      return pyIsSource(node) || pyTainted(node.childForFieldName("object") ?? node.childForFieldName("value"), tainted);
    case "call": {
      if (pyIsSource(node)) return true;
      const fn = node.childForFieldName("function");
      return !!fn && fn.type === "attribute" && pyTainted(fn.childForFieldName("object"), tainted);
    }
    case "binary_operator":
      return pyTainted(node.childForFieldName("left"), tainted) || pyTainted(node.childForFieldName("right"), tainted);
    case "string":
    case "concatenated_string":
      return pyStringHasTaint(node, tainted);
    case "parenthesized_expression":
    case "conditional_expression": {
      for (let i = 0; i < node.namedChildCount; i++) { const c = node.namedChild(i); if (c && pyTainted(c, tainted)) return true; }
      return false;
    }
    default:
      return pyIsSource(node);
  }
}

/** call の最初の位置引数（keyword_argument は除く）。 */
function pyFirstArg(call: TsNode): TsNode | null {
  const args = call.childForFieldName("arguments");
  if (!args) return null;
  for (let i = 0; i < args.namedChildCount; i++) {
    const c = args.namedChild(i);
    if (c && c.type !== "keyword_argument") return c;
  }
  return null;
}

/** scope 本体を walk（nested 関数の中には入らない）。 */
function pyWalkScope(scope: TsNode, visit: (n: TsNode) => void): void {
  const rec = (n: TsNode, isRoot: boolean): void => {
    if (!isRoot && PY_SCOPE_TYPES.has(n.type)) return;
    visit(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c, false); }
  };
  rec(scope, true);
}

type PySinkHit = { ruleId: string; node: TsNode };

/** fixpoint で汚染変数を収集（seed は初期汚染名）。 */
function pyCollectTainted(scope: TsNode, seed: Iterable<string>): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true, guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    pyWalkScope(scope, (n) => {
      if (n.type === "assignment" || n.type === "augmented_assignment") {
        const left = n.childForFieldName("left");
        if (left && left.type === "identifier" && !tainted.has(left.text) && pyTainted(n.childForFieldName("right"), tainted)) {
          tainted.add(left.text); changed = true;
        }
      }
    });
  }
  return tainted;
}

/** scope 内の sink を検出（hit を返す）。 */
function pyScanSinks(scope: TsNode, tainted: Set<string>): PySinkHit[] {
  const hits: PySinkHit[] = [];
  const hit = (ruleId: string, node: TsNode): void => { hits.push({ ruleId, node }); };
  pyWalkScope(scope, (n) => {
    if (n.type !== "call") return;
    const fn = n.childForFieldName("function");
    const arg0 = pyFirstArg(n);
    if (!fn) return;
    // pre-filter: いずれかの位置引数が汚染（LDAP など tainted 引数が arg0 でない sink 用）
    const arg0Tainted = pyTainted(arg0, tainted);
    const anyArgTainted = arg0Tainted || pyPosArgs(n).some((a) => pyTainted(a, tainted));
    if (!anyArgTainted) return;
    const ft = fn.text;
    if (fn.type === "identifier") {
      if (!arg0Tainted) return;
      if (ft === "eval" || ft === "exec") hit("taint.py.code_injection", n);
      else if (ft === "open") hit("taint.py.path_traversal", n);
      else if (ft === "urlopen") hit("taint.py.ssrf", n);
      else if (ft === "render_template_string") hit("taint.py.ssti", n);
      else if (ft === "HttpResponse" || ft === "make_response" || ft === "Response") hit("taint.py.xss", n);
    } else if (fn.type === "attribute") {
      // LDAP は filter が arg2 のため any-arg で判定。他は arg0 汚染を要求。
      if ((ft.endsWith(".search_s") || ft.endsWith(".search_ext_s"))) { hit("taint.py.ldap_injection", n); return; }
      if (!arg0Tainted) return;
      if (ft === "os.system" || ft === "os.popen") hit("taint.py.command_injection", n);
      else if (ft.startsWith("subprocess.") && argsHaveShellTrue(n.childForFieldName("arguments"))) hit("taint.py.command_injection", n);
      else if (ft.endsWith(".execute") || ft.endsWith(".executemany") || ft.endsWith(".raw")) hit("taint.py.sql_injection", n);
      else if (ft.startsWith("requests.") || ft.endsWith(".urlopen")) hit("taint.py.ssrf", n);
      else if (ft.endsWith(".render_template_string")) hit("taint.py.ssti", n);
      else if (ft === "pickle.loads" || ft === "pickle.load" || ft === "yaml.load") hit("taint.py.deserialization", n);
      else if (PY_MONGO_METHODS.some((m) => ft.endsWith(`.${m}`))) hit("taint.py.nosql_injection", n);
      else if (PY_XML_PARSE.some((m) => ft.endsWith(m))) hit("taint.py.xxe", n);
      else if (ft.endsWith(".xpath")) hit("taint.py.xpath_injection", n);
    }
  });
  return hits;
}

/** function_definition の parameter 名リスト。 */
function pyParamNames(fnDef: TsNode): string[] {
  const params = fnDef.childForFieldName("parameters");
  const names: string[] = [];
  if (!params) return names;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p) { names.push(""); continue; }
    if (p.type === "identifier") names.push(p.text);
    else {
      const id = p.childForFieldName("name") ?? p.namedChild(0);
      names.push(id && id.type === "identifier" ? id.text : "");
    }
  }
  return names;
}

/** call の位置引数（keyword_argument を除く）。 */
function pyPosArgs(call: TsNode): TsNode[] {
  const args = call.childForFieldName("arguments");
  const out: TsNode[] = [];
  if (args) for (let i = 0; i < args.namedChildCount; i++) { const c = args.namedChild(i); if (c && c.type !== "keyword_argument") out.push(c); }
  return out;
}

/** ローカル関数定義を収集（inter-procedural 用）。 */
function pyCollectFunctions(root: TsNode): Map<string, { params: string[]; scope: TsNode }> {
  const fns = new Map<string, { params: string[]; scope: TsNode }>();
  const rec = (n: TsNode): void => {
    if (n.type === "function_definition") {
      const name = n.childForFieldName("name");
      if (name && name.type === "identifier") fns.set(name.text, { params: pyParamNames(n), scope: n });
    }
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) rec(c); }
  };
  rec(root);
  return fns;
}

/** Python の source→sink taint 検出（intra + one-level inter-procedural）。 */
function detectTaint(root: TsNode, path: string, text: string): CanonicalFinding[] {
  const out: CanonicalFinding[] = [];
  const seen = new Set<string>();
  const add = (ruleId: string, node: TsNode): void => {
    const rule = PY_TAINT_RULES[ruleId];
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

  // inter-procedural（multi-level）: 関数サマリ(param→sink)を call graph 上で fixpoint 伝播
  const functions = pyCollectFunctions(root);
  const paramSinks = new Map<string, Map<number, PySinkHit[]>>();
  const hitKey = (h: PySinkHit): string => `${h.ruleId}@${h.node.startPosition.row}:${h.node.startPosition.column}`;
  let sumChanged = true, sumGuard = 0;
  while (sumChanged && sumGuard++ < functions.size + 5) {
    sumChanged = false;
    for (const [name, fn] of functions) {
      fn.params.forEach((p, i) => {
        if (!p) return;
        const tainted = pyCollectTainted(fn.scope, [p]);
        const hits: PySinkHit[] = pyScanSinks(fn.scope, tainted); // 直接 sink
        // 多段: 汚染引数で別のローカル関数を呼ぶ → callee の param-sink を引き継ぐ
        pyWalkScope(fn.scope, (n) => {
          if (n.type !== "call") return;
          const cfn = n.childForFieldName("function");
          if (!cfn || cfn.type !== "identifier" || cfn.text === name) return;
          const cps = paramSinks.get(cfn.text);
          if (!cps) return;
          const posArgs = pyPosArgs(n);
          for (const [j, chits] of cps) if (pyTainted(posArgs[j] ?? null, tainted)) hits.push(...chits);
        });
        if (!hits.length) return;
        let perParam = paramSinks.get(name);
        if (!perParam) { perParam = new Map(); paramSinks.set(name, perParam); }
        const existing = perParam.get(i) ?? [];
        const keys = new Set(existing.map(hitKey));
        let added = false;
        for (const h of hits) if (!keys.has(hitKey(h))) { existing.push(h); keys.add(hitKey(h)); added = true; }
        if (added) { perParam.set(i, existing); sumChanged = true; }
      });
    }
  }

  const scopes: TsNode[] = [];
  const collect = (n: TsNode): void => {
    if (n.type === "module" || PY_SCOPE_TYPES.has(n.type)) scopes.push(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) collect(c); }
  };
  collect(root);

  for (const scope of scopes) {
    const tainted = pyCollectTainted(scope, []);
    for (const h of pyScanSinks(scope, tainted)) add(h.ruleId, h.node);
    // inter-proc: ローカル関数を汚染引数で呼ぶ → callee 内 sink を報告
    pyWalkScope(scope, (n) => {
      if (n.type !== "call") return;
      const fn = n.childForFieldName("function");
      if (!fn || fn.type !== "identifier") return;
      const perParam = paramSinks.get(fn.text);
      if (!perParam) return;
      const posArgs = pyPosArgs(n);
      for (const [i, hits] of perParam) {
        if (pyTainted(posArgs[i] ?? null, tainted)) for (const h of hits) add(h.ruleId, h.node);
      }
    });
  }
  return out;
}

/** tree-sitter Python を init し、engine にバックエンドを登録する。 */
export async function initPython(): Promise<void> {
  if (parser) return;
  parser = (await loadParser(PY_GRAMMAR_WASM_B64)) as { parse(s: string): { rootNode: TsNode } };
  registerAstBackend({ exts: new Set(["py"]), detect, coveredRuleIds: COVERED });
}

function argsHaveShellTrue(args: TsNode | null): boolean {
  if (!args) return false;
  for (let i = 0; i < args.childCount; i++) {
    const c = args.child(i);
    if (c && c.type === "keyword_argument") {
      const name = c.childForFieldName("name");
      const val = c.childForFieldName("value");
      if (name?.text === "shell" && val?.text === "True") return true;
    }
  }
  return false;
}

/** Python ソースを tree-sitter で AST 検出。 */
function detect(path: string, text: string): CanonicalFinding[] {
  if (!parser) return [];
  let root: TsNode;
  try {
    root = parser.parse(text).rootNode;
  } catch {
    return [];
  }

  const out: CanonicalFinding[] = [];
  const seen = new Set<string>();

  const add = (ruleId: string, node: TsNode): void => {
    const rule = RULE_BY_ID.get(ruleId);
    if (!rule) return;
    const snippet = node.text.slice(0, 60);
    const locator = sha256(`${ruleId}:${snippet}`);
    const fingerprint = canonicalHash({ rule_id: ruleId, path, locator });
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    out.push({
      schema_version: SCHEMA_VERSION,
      kind: "sast_pattern",
      rule_id: rule.id,
      cwe: rule.cwe,
      owasp: rule.owasp,
      severity: rule.severity,
      confidence: "confirmed", // AST 確定
      title: rule.title,
      message: rule.message,
      location: {
        path,
        start_line: node.startPosition.row + 1,
        start_col: node.startPosition.column + 1,
        end_line: node.endPosition.row + 1,
        end_col: node.endPosition.column + 1,
      },
      snippet_hash: fingerprint,
      remediation: rule.remediation,
      references: rule.references,
      fingerprint,
    });
  };

  const walk = (node: TsNode): void => {
    if (node.type === "call") {
      const fn = node.childForFieldName("function");
      const args = node.childForFieldName("arguments");
      if (fn) {
        if (fn.type === "identifier") {
          if (fn.text === "eval") add("pattern.py.eval", node);
          else if (fn.text === "exec") add("pattern.py.exec", node);
        } else if (fn.type === "attribute") {
          const ft = fn.text;
          if (ft === "os.system") add("pattern.py.os_system", node);
          else if (ft.startsWith("subprocess.") && argsHaveShellTrue(args)) add("pattern.py.subprocess_shell_true", node);
        }
      }
    }
    for (let i = 0; i < node.childCount; i++) {
      const c = node.child(i);
      if (c) walk(c);
    }
  };
  walk(root);
  out.push(...detectTaint(root, path, text)); // source→sink taint

  out.sort((a, b) =>
    a.location.start_line !== b.location.start_line
      ? a.location.start_line - b.location.start_line
      : a.location.start_col - b.location.start_col,
  );
  return out;
}
