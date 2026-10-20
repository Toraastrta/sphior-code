/**
 * taint-js.ts — JS/TS の intra-procedural taint 解析（Tier 4・データフロー解析の本体）
 *
 * 「危険な書き方」ではなく「**信頼できない入力（source）が危険な地点（sink）へ
 * 到達する本物の脆弱性**」を検出する。関数スコープ内で source から始まる汚染を
 * 変数代入で伝播（fixpoint）し、sink 引数が汚染されていれば finding を出す。
 *
 * 決定論・再現性は不変。over-approx を避けるためスコープを関数単位に区切る
 * （同名変数の跨ぎ FP を抑制）。nested 関数は別スコープ（closure 経由の汚染は
 * 取りこぼす＝FP より FN を選ぶ）。source→sink の直接/代入フローに限定。
 */

import type { CanonicalFinding, Severity } from "../types";
import { SCHEMA_VERSION } from "../types";
import { sha256, canonicalHash } from "../canonical";
import { walk, calleeName, calleeMethodName, type AstNode } from "./ast-js";

interface TaintRule {
  id: string;
  cwe: string;
  owasp: string;
  severity: Severity;
  title: string;
  message: string;
  remediation: string;
}

const REF = (n: string) => [`https://cwe.mitre.org/data/definitions/${n}.html`];

const TAINT_RULES: Record<string, TaintRule & { references: string[] }> = {
  "taint.js.command_injection": {
    id: "taint.js.command_injection", cwe: "CWE-78", owasp: "A03:2021", severity: "critical",
    title: "Command injection (untrusted input → shell)",
    message: "Untrusted input flows into a shell command (exec/execSync) — OS command injection.",
    remediation: "Use execFile/spawn with an argument array; never build shell strings from input.",
    references: REF("78"),
  },
  "taint.js.code_injection": {
    id: "taint.js.code_injection", cwe: "CWE-95", owasp: "A03:2021", severity: "critical",
    title: "Code injection (untrusted input → eval)",
    message: "Untrusted input flows into eval()/new Function() — arbitrary code execution.",
    remediation: "Never evaluate untrusted input; use safe parsing / explicit logic.",
    references: REF("95"),
  },
  "taint.js.sql_injection": {
    id: "taint.js.sql_injection", cwe: "CWE-89", owasp: "A03:2021", severity: "critical",
    title: "SQL injection (untrusted input → query)",
    message: "Untrusted input is concatenated/interpolated into a SQL query.",
    remediation: "Use parameterized queries / prepared statements; never build SQL from input.",
    references: REF("89"),
  },
  "taint.js.xss": {
    id: "taint.js.xss", cwe: "CWE-79", owasp: "A03:2021", severity: "high",
    title: "XSS (untrusted input → HTML sink)",
    message: "Untrusted input reaches an HTML sink (innerHTML / document.write).",
    remediation: "Sanitize with a vetted sanitizer, or use safe DOM APIs (textContent).",
    references: REF("79"),
  },
  "taint.js.ssrf": {
    id: "taint.js.ssrf", cwe: "CWE-918", owasp: "A10:2021", severity: "high",
    title: "SSRF (untrusted input → outbound request URL)",
    message: "Untrusted input controls an outbound request URL (fetch/axios/http) — server-side request forgery.",
    remediation: "Allowlist hosts/schemes; never fetch a URL built from raw input.",
    references: REF("918"),
  },
  "taint.js.path_traversal": {
    id: "taint.js.path_traversal", cwe: "CWE-22", owasp: "A01:2021", severity: "high",
    title: "Path traversal (untrusted input → filesystem path)",
    message: "Untrusted input controls a filesystem path (fs.*) — path traversal / arbitrary file access.",
    remediation: "Resolve and validate the path against an allowed base dir; reject '..'.",
    references: REF("22"),
  },
  "taint.js.open_redirect": {
    id: "taint.js.open_redirect", cwe: "CWE-601", owasp: "A01:2021", severity: "medium",
    title: "Open redirect (untrusted input → redirect target)",
    message: "Untrusted input controls a redirect target (res/NextResponse.redirect) — open redirect / phishing.",
    remediation: "Redirect only to allowlisted internal paths; validate the target.",
    references: REF("601"),
  },
  "taint.js.nosql_injection": {
    id: "taint.js.nosql_injection", cwe: "CWE-943", owasp: "A03:2021", severity: "high",
    title: "NoSQL injection (untrusted object → query)",
    message: "An untrusted object is passed as a MongoDB query — attacker-controlled operators ($where/$gt) enable NoSQL injection.",
    remediation: "Never pass req.body/query directly as a filter; validate/whitelist fields and coerce types.",
    references: REF("943"),
  },
  "taint.js.header_injection": {
    id: "taint.js.header_injection", cwe: "CWE-113", owasp: "A03:2021", severity: "medium",
    title: "HTTP header injection (untrusted input → response header)",
    message: "Untrusted input sets a response header value — header injection / response splitting / open redirect.",
    remediation: "Validate header values; strip CR/LF; use an allowlist for Location.",
    references: REF("113"),
  },
  "taint.js.prototype_pollution": {
    id: "taint.js.prototype_pollution", cwe: "CWE-1321", owasp: "A08:2021", severity: "high",
    title: "Prototype pollution (untrusted object → deep merge)",
    message: "An untrusted object is deep-merged/assigned into another object — __proto__ pollution can lead to RCE/DoS.",
    remediation: "Never merge req.body/query into objects; use a safe merge, freeze prototypes, or validate keys.",
    references: REF("1321"),
  },
};
const HEADER_SET_METHODS = new Set(["setHeader", "header", "append"]);
const MERGE_METHODS = new Set(["merge", "mergeWith", "defaultsDeep", "set", "setWith"]);

const MONGO_QUERY_METHODS = new Set([
  "find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace",
  "updateOne", "updateMany", "deleteOne", "deleteMany", "aggregate", "count", "countDocuments", "distinct",
]);

const REDIRECT_CALLS = new Set(["res.redirect", "response.redirect", "NextResponse.redirect", "Response.redirect"]);

const FS_METHODS = new Set([
  "readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
  "createReadStream", "createWriteStream", "unlink", "unlinkSync", "readdir", "readdirSync",
  "open", "openSync", "stat", "statSync", "readlink", "rm", "rmSync",
]);
const HTTP_CLIENT_OBJECTS = new Set(["axios", "http", "https", "got", "superagent"]);
const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "request"]);

// source: 信頼できない入力の起点（member path prefix）
// 注: process.env は operator 設定＝信頼済みなので source に含めない（FP 回避）。
//     process.argv も CLI operator 起動のため含めない（Web 文脈で FP になりやすい）。
const SOURCE_PREFIXES = [
  "req.query", "req.body", "req.params", "req.headers", "req.cookies",
  "request.query", "request.body", "request.params", "request.headers", "request.cookies",
  "location.search", "location.hash", "location.href",
  "document.URL", "document.cookie", "document.referrer",
  "window.name",
];
// source: 呼び出し形の入力取得（末尾一致。req.nextUrl.searchParams.get 等も拾う）
const SOURCE_CALL_SUFFIXES = [
  "req.get", "req.header", "req.param", "request.get", "request.header", "request.param",
  "searchParams.get", "searchParams.getAll", "formData.get", "urlParams.get",
];

// 汚染を素通しするラッパ構築子。`new URLSearchParams(location.search)` は
// 引数の汚染をそのままオブジェクトへ運ぶので、戻り値も汚染として扱う。
//
// これが無いと検出が**変数名に依存**した。SOURCE_CALL_SUFFIXES は末尾一致なので
// `searchParams.get()` は拾えるが `params.get()` は拾えず、同じコードでも
// 変数名を params にした途端 XSS を見逃していた（2026-10-20 実測）。
// 値を保持して読み出す型だけに限定する（RegExp/Error 等は別の問題なので入れない）。
const TAINT_WRAPPER_CTORS = new Set(["URLSearchParams", "URL"]);

// スコープ境界（nested 関数は別スコープ）
const SCOPE_TYPES = new Set([
  "FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression",
  "ObjectMethod", "ClassMethod", "ClassPrivateMethod",
]);
const SKIP_KEYS = new Set(["loc", "leadingComments", "trailingComments", "comments", "tokens", "range"]);

/** member 式の静的パス（a.b.c）。computed は object のパスに畳む。 */
function memberPath(node: AstNode | undefined): string | null {
  if (!node) return null;
  if (node.type === "Identifier") return typeof node.name === "string" ? node.name : null;
  if (node.type === "MemberExpression") {
    const objPath = memberPath(node.object as AstNode | undefined);
    if (!objPath) return null;
    if (node.computed) return objPath;
    const prop = node.property as AstNode | undefined;
    const name = prop && prop.type === "Identifier" ? (prop.name as string) : null;
    return name ? `${objPath}.${name}` : objPath;
  }
  return null;
}

function isSourceExpr(node: AstNode | undefined): boolean {
  if (!node) return false;
  if (node.type === "MemberExpression") {
    const p = memberPath(node);
    return !!p && SOURCE_PREFIXES.some((s) => p === s || p.startsWith(`${s}.`));
  }
  if (node.type === "CallExpression") {
    const callee = node.callee as AstNode | undefined;
    if (callee && callee.type === "MemberExpression") {
      const p = memberPath(callee);
      return !!p && SOURCE_CALL_SUFFIXES.some((s) => p === s || p.endsWith(`.${s}`));
    }
  }
  return false;
}

/** 式が汚染されているか（source を含む or 汚染変数を参照）。 */
function exprIsTainted(node: AstNode | undefined, tainted: Set<string>): boolean {
  if (!node || typeof node !== "object") return false;
  switch (node.type) {
    case "Identifier":
      return typeof node.name === "string" && tainted.has(node.name);
    case "MemberExpression":
      return isSourceExpr(node) || exprIsTainted(node.object as AstNode, tainted);
    case "CallExpression": {
      if (isSourceExpr(node)) return true;
      const callee = node.callee as AstNode | undefined;
      return !!callee && callee.type === "MemberExpression" && exprIsTainted(callee.object as AstNode, tainted);
    }
    case "TemplateLiteral":
      return ((node.expressions as AstNode[] | undefined) ?? []).some((e) => exprIsTainted(e, tainted));
    case "BinaryExpression":
      return node.operator === "+" && (exprIsTainted(node.left as AstNode, tainted) || exprIsTainted(node.right as AstNode, tainted));
    case "LogicalExpression":
      return exprIsTainted(node.left as AstNode, tainted) || exprIsTainted(node.right as AstNode, tainted);
    case "ConditionalExpression":
      return exprIsTainted(node.consequent as AstNode, tainted) || exprIsTainted(node.alternate as AstNode, tainted);
    case "NewExpression": {
      // new URLSearchParams(<汚染>) / new URL(<汚染>) の戻り値は汚染。
      // 以降 .get() / .searchParams.get() は CallExpression 側の
      // callee.object 判定で自然に汚染として伝わる。
      const ctor = calleeName(node);
      if (!ctor || !TAINT_WRAPPER_CTORS.has(ctor)) return false;
      return ((node.arguments as AstNode[] | undefined) ?? []).some((a) => exprIsTainted(a, tainted));
    }
    case "ParenthesizedExpression":
    case "TSAsExpression":
    case "TSNonNullExpression":
    case "AwaitExpression":
      return exprIsTainted((node.expression ?? node.argument) as AstNode, tainted);
    default:
      return isSourceExpr(node);
  }
}

/** スコープ本体を walk（nested 関数の中には入らない）。 */
function walkScope(scope: AstNode, visit: (n: AstNode) => void): void {
  const rec = (n: unknown, isRoot: boolean): void => {
    if (!n || typeof n !== "object") return;
    if (Array.isArray(n)) {
      for (const c of n) rec(c, false);
      return;
    }
    const obj = n as Record<string, unknown>;
    if (!isRoot && typeof obj.type === "string" && SCOPE_TYPES.has(obj.type)) return; // nested scope
    if (typeof obj.type === "string") visit(obj as AstNode);
    for (const key of Object.keys(obj)) {
      if (SKIP_KEYS.has(key)) continue;
      rec(obj[key], false);
    }
  };
  rec(scope, true);
}

type SinkHit = { ruleId: string; node: AstNode };

/** fixpoint で汚染変数を収集（seed は初期汚染名＝source 扱い）。 */
function collectTainted(scope: AstNode, seed: Iterable<string>): Set<string> {
  const tainted = new Set<string>(seed);
  let changed = true;
  let guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    walkScope(scope, (n) => {
      if (n.type === "VariableDeclarator") {
        const id = n.id as AstNode | undefined;
        if (id && id.type === "Identifier" && typeof id.name === "string" && !tainted.has(id.name)) {
          if (exprIsTainted(n.init as AstNode | undefined, tainted)) { tainted.add(id.name); changed = true; }
        }
      } else if (n.type === "AssignmentExpression") {
        const left = n.left as AstNode | undefined;
        if (left && left.type === "Identifier" && typeof left.name === "string" && !tainted.has(left.name)) {
          if (exprIsTainted(n.right as AstNode | undefined, tainted)) { tainted.add(left.name); changed = true; }
        }
      }
    });
  }
  return tainted;
}

/** スコープ内の sink を検出（tainted set を受け hit を返す。intra/inter で共有）。 */
function scanSinks(scope: AstNode, tainted: Set<string>): SinkHit[] {
  const hits: SinkHit[] = [];
  const hit = (ruleId: string, node: AstNode): void => { hits.push({ ruleId, node }); };
  walkScope(scope, (n) => {
    if (n.type === "CallExpression") {
      const arg0 = (n.arguments as AstNode[] | undefined)?.[0];
      const idName = calleeName(n);
      const method = calleeMethodName(n);
      const callee = n.callee as AstNode | undefined;
      const objPath = callee && callee.type === "MemberExpression" ? memberPath(callee.object as AstNode) : null;
      if ((method === "exec" || method === "execSync") && exprIsTainted(arg0, tainted)) hit("taint.js.command_injection", n);
      else if ((idName === "eval" || idName === "require") && exprIsTainted(arg0, tainted)) hit("taint.js.code_injection", n);
      else if (objPath === "vm" && !!method && ["runInContext", "runInNewContext", "runInThisContext", "compileFunction"].includes(method) && exprIsTainted(arg0, tainted)) hit("taint.js.code_injection", n);
      else if ((method === "query" || method === "raw" || method === "execute") && exprIsTainted(arg0, tainted)) hit("taint.js.sql_injection", n);
      else if (memberPath(callee) === "document.write" && exprIsTainted(arg0, tainted)) hit("taint.js.xss", n);
      else if (
        ((idName === "fetch" || idName === "axios" || idName === "got") && exprIsTainted(arg0, tainted)) ||
        (!!method && HTTP_METHODS.has(method) && !!objPath && HTTP_CLIENT_OBJECTS.has(objPath) && exprIsTainted(arg0, tainted))
      ) hit("taint.js.ssrf", n);
      else if (!!method && FS_METHODS.has(method) && !!objPath && (objPath === "fs" || objPath === "fs.promises" || objPath === "fsp") && exprIsTainted(arg0, tainted)) hit("taint.js.path_traversal", n);
      else if (REDIRECT_CALLS.has(memberPath(callee) ?? "") && exprIsTainted(arg0, tainted)) hit("taint.js.open_redirect", n);
      // 反射型 XSS: res.send/write/end に汚染をそのまま返す（Express 等）
      else if (!!method && ["send", "write", "end"].includes(method) && !!objPath && (objPath === "res" || objPath === "response") && exprIsTainted(arg0, tainted)) hit("taint.js.xss", n);
      // NoSQL injection: 汚染オブジェクトを丸ごとクエリに渡す（Mongo）。ObjectExpression は
      // 直接汚染にならないので、req.body/query をそのまま渡した時だけ発火＝低 FP。
      else if (!!method && MONGO_QUERY_METHODS.has(method) && exprIsTainted(arg0, tainted)) hit("taint.js.nosql_injection", n);
      // header injection: res.setHeader(name, tainted) の値が汚染（arg1）
      else if (!!method && HEADER_SET_METHODS.has(method) && !!objPath && (objPath === "res" || objPath === "response") && exprIsTainted((n.arguments as AstNode[] | undefined)?.[1], tainted)) hit("taint.js.header_injection", n);
      // prototype pollution: _.merge(x, tainted) / Object.assign(target, tainted)
      else if (
        (!!method && MERGE_METHODS.has(method) && (objPath === "_" || objPath === "lodash") &&
          ((n.arguments as AstNode[] | undefined) ?? []).some((a) => exprIsTainted(a, tainted))) ||
        (memberPath(callee) === "Object.assign" &&
          ((n.arguments as AstNode[] | undefined) ?? []).slice(1).some((a) => exprIsTainted(a, tainted)))
      ) hit("taint.js.prototype_pollution", n);
    } else if (n.type === "NewExpression") {
      if (calleeName(n) === "Function" && ((n.arguments as AstNode[] | undefined) ?? []).some((a) => exprIsTainted(a, tainted))) hit("taint.js.code_injection", n);
    } else if (n.type === "AssignmentExpression") {
      const left = n.left as AstNode | undefined;
      if (left && left.type === "MemberExpression") {
        const prop = left.property as AstNode | undefined;
        const pname = prop && prop.type === "Identifier" ? prop.name : undefined;
        if ((pname === "innerHTML" || pname === "outerHTML") && exprIsTainted(n.right as AstNode | undefined, tainted)) hit("taint.js.xss", n);
      }
    }
  });
  return hits;
}

/** parameter 名リスト（default は left を採用・分割は簡略化）。 */
function paramNames(fn: AstNode): string[] {
  return ((fn.params as AstNode[] | undefined) ?? []).map((p) => {
    if (p.type === "Identifier") return typeof p.name === "string" ? p.name : "";
    if (p.type === "AssignmentPattern") {
      const l = p.left as AstNode | undefined;
      return l && l.type === "Identifier" ? (l.name as string) : "";
    }
    return "";
  });
}

/** ローカル関数定義を収集（名前→params/scope）。inter-procedural 用。 */
function collectLocalFunctions(ast: unknown): Map<string, { params: string[]; scope: AstNode }> {
  const fns = new Map<string, { params: string[]; scope: AstNode }>();
  walk(ast, (n) => {
    if (n.type === "FunctionDeclaration") {
      const id = n.id as AstNode | undefined;
      if (id && id.type === "Identifier" && typeof id.name === "string") fns.set(id.name, { params: paramNames(n), scope: n });
    } else if (n.type === "VariableDeclarator") {
      const id = n.id as AstNode | undefined;
      const init = n.init as AstNode | undefined;
      if (id && id.type === "Identifier" && typeof id.name === "string" && init &&
          (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression")) {
        fns.set(id.name, { params: paramNames(init), scope: init });
      }
    }
  });
  return fns;
}

/** parse 済み AST から taint finding を検出（intra + one-level inter-procedural）。 */
export function detectTaintFromAst(ast: unknown, path: string, text: string): CanonicalFinding[] {
  const out: CanonicalFinding[] = [];
  const seen = new Set<string>();

  const addFinding = (ruleId: string, node: AstNode): void => {
    const rule = TAINT_RULES[ruleId];
    if (!rule || !node.loc) return;
    const snippet =
      node.start != null && node.end != null ? text.slice(node.start, Math.min(node.end, node.start + 80)) : ruleId;
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
      confidence: "likely", // intra-proc 近似のため likely
      title: rule.title,
      message: rule.message,
      location: {
        path,
        start_line: node.loc.start.line,
        start_col: node.loc.start.column + 1,
        end_line: node.loc.end.line,
        end_col: node.loc.end.column + 1,
      },
      snippet_hash: fingerprint,
      remediation: rule.remediation,
      references: rule.references,
      fingerprint,
    });
  };

  // inter-procedural（multi-level）: 各ローカル関数の「param i が sink へ到達するか」を
  // call graph 上で fixpoint 伝播して要約する。直接 sink に加え、汚染引数で別のローカル
  // 関数を呼び、その callee の param-sink に到達する経路も引き継ぐ（多段フロー）。
  const functions = collectLocalFunctions(ast);
  const paramSinks = new Map<string, Map<number, SinkHit[]>>();
  const hitKey = (h: SinkHit): string => `${h.ruleId}@${(h.node.start as number | undefined) ?? -1}`;
  let sumChanged = true;
  let sumGuard = 0;
  while (sumChanged && sumGuard++ < functions.size + 5) {
    sumChanged = false;
    for (const [name, fn] of functions) {
      fn.params.forEach((p, i) => {
        if (!p) return;
        const tainted = collectTainted(fn.scope, [p]);
        const hits: SinkHit[] = scanSinks(fn.scope, tainted); // 直接 sink
        // 多段: 汚染引数で別のローカル関数を呼ぶ → callee の param-sink を引き継ぐ
        walkScope(fn.scope, (n) => {
          if (n.type !== "CallExpression") return;
          const callee = calleeName(n);
          if (!callee || callee === name) return; // 直接再帰は直接 sink で足りる
          const cps = paramSinks.get(callee);
          if (!cps) return;
          const args = (n.arguments as AstNode[] | undefined) ?? [];
          for (const [j, chits] of cps) if (exprIsTainted(args[j], tainted)) hits.push(...chits);
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

  // スコープ群（Program + 各関数）
  const scopes: AstNode[] = [];
  walk(ast, (n) => {
    if (n.type === "Program" || SCOPE_TYPES.has(n.type)) scopes.push(n);
  });

  for (const scope of scopes) {
    const tainted = collectTainted(scope, []);
    // intra-proc sink
    for (const h of scanSinks(scope, tainted)) addFinding(h.ruleId, h.node);
    // inter-proc: ローカル関数を汚染引数で呼ぶ → callee 内の param-sink を報告
    walkScope(scope, (n) => {
      if (n.type !== "CallExpression") return;
      const name = calleeName(n);
      if (!name) return;
      const perParam = paramSinks.get(name);
      if (!perParam) return;
      const args = (n.arguments as AstNode[] | undefined) ?? [];
      for (const [i, hits] of perParam) {
        if (exprIsTainted(args[i], tainted)) for (const h of hits) addFinding(h.ruleId, h.node);
      }
    });
  }

  out.sort((a, b) =>
    a.location.start_line !== b.location.start_line
      ? a.location.start_line - b.location.start_line
      : a.location.start_col !== b.location.start_col
        ? a.location.start_col - b.location.start_col
        : a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0,
  );
  return out;
}
