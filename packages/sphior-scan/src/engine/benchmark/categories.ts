/**
 * categories.ts — OWASP Benchmark カテゴリ ↔ CWE のマッピング（測定パイプライン M1）
 *
 * OWASP Benchmark（Java テストスイート）は各テストケースを 11 カテゴリのいずれかに分類し、
 * 「real vulnerability = true/false」でラベル付けする。ツールの成績は、そのカテゴリの CWE を
 * 当該ファイルに報告できたか否かで測る（他カテゴリの検出はそのカテゴリの採点に数えない
 * = Benchmark 公式方法論）。
 *
 * ここでは 2 方向を定義する:
 *   - CATEGORY_CWES: カテゴリ → 「検出とみなす CWE 集合」。SPHIOR エンジンが出す CWE 表記の
 *     ゆらぎ（弱ハッシュを CWE-327 で出す等）を吸収するため、単一 CWE でなく集合で持つ。
 *   - detectedCategories(): finding の CWE 群 → 命中カテゴリ集合。
 *
 * 数値は推測せず、Benchmark の各カテゴリ定義（expectedresults CSV の cwe 列と公式ドキュメント）に
 * 準拠する。マッピングを変えたら score のテストで基準が動くため、変更は意図的に行うこと。
 */

/** OWASP Benchmark の 11 カテゴリ（CSV の category 列に現れる正準名）。 */
export const BENCHMARK_CATEGORIES = [
  "pathtraver",   // Path Traversal — CWE-22
  "cmdi",         // Command Injection — CWE-78
  "sqli",         // SQL Injection — CWE-89
  "xss",          // Cross-Site Scripting — CWE-79
  "ldapi",        // LDAP Injection — CWE-90
  "xpathi",       // XPath Injection — CWE-643
  "crypto",       // Weak Encryption — CWE-327
  "hash",         // Weak Hashing — CWE-328（ツールは 327 で出すことが多い）
  "weakrand",     // Weak Randomness — CWE-330
  "securecookie", // Insecure Cookie — CWE-614
  "trustbound",   // Trust Boundary Violation — CWE-501
] as const;

export type BenchmarkCategory = (typeof BENCHMARK_CATEGORIES)[number];

/**
 * カテゴリ → 「検出とみなす CWE 集合」。
 * hash は Benchmark 上 CWE-328 だが、SPHIOR の weak_digest ルールは弱ハッシュを CWE-327 で出す
 * ため 327/326 も命中に含める（弱ハッシュを暗号弱化として報告するツール慣行の吸収）。
 * weakrand は 330 が正準だが 338（暗号用途の弱 PRNG）も許容する。
 */
export const CATEGORY_CWES: Record<BenchmarkCategory, ReadonlySet<number>> = {
  pathtraver:   new Set([22]),
  cmdi:         new Set([78]),
  sqli:         new Set([89]),
  xss:          new Set([79, 80]),
  ldapi:        new Set([90]),
  xpathi:       new Set([643]),
  crypto:       new Set([327, 326]),
  hash:         new Set([328, 327, 326]),
  weakrand:     new Set([330, 338]),
  securecookie: new Set([614]),
  trustbound:   new Set([501]),
};

/** "CWE-89" / "cwe-89" / "89" / 89 → 89（数値）。不正は null。 */
export function parseCweNumber(cwe: string | number | null | undefined): number | null {
  if (cwe == null) return null;
  if (typeof cwe === "number") return Number.isFinite(cwe) ? cwe : null;
  const m = String(cwe).match(/(\d+)/);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

/**
 * finding が持つ CWE 群から、命中する Benchmark カテゴリ集合を返す。
 * 1 つの CWE が複数カテゴリ（crypto/hash の 327 等）に命中しうるため集合で返す。
 */
export function detectedCategories(cwes: Array<string | number | null | undefined>): Set<BenchmarkCategory> {
  const nums = new Set<number>();
  for (const c of cwes) {
    const n = parseCweNumber(c);
    if (n != null) nums.add(n);
  }
  const hit = new Set<BenchmarkCategory>();
  for (const cat of BENCHMARK_CATEGORIES) {
    const wanted = CATEGORY_CWES[cat];
    for (const n of nums) {
      if (wanted.has(n)) { hit.add(cat); break; }
    }
  }
  return hit;
}

/** 文字列が既知の Benchmark カテゴリか。 */
export function isBenchmarkCategory(v: string): v is BenchmarkCategory {
  return (BENCHMARK_CATEGORIES as readonly string[]).includes(v);
}
