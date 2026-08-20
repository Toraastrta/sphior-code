/**
 * expected-results.ts — OWASP Benchmark の expectedresults CSV パーサ（測定パイプライン M2）
 *
 * Benchmark は `expectedresults-<ver>.csv`（例: expectedresults-1.2.csv）に各テストケースの
 * 正解ラベルを持つ。フォーマット（ヘッダ + カンマ区切り）:
 *
 *   # test name, category, real vulnerability, cwe,
 *   BenchmarkTest00001,pathtraver,true,22,
 *   BenchmarkTest00002,securecookie,false,614,
 *
 * 生成器/バージョンにより末尾カンマ・CRLF・空行・大文字ゆらぎがあるため堅牢に読む。
 * カテゴリ列を正解の真とし（cwe 列は補助）、未知カテゴリ行は skip（推測で埋めない）。
 */

import { isBenchmarkCategory, parseCweNumber, type BenchmarkCategory } from "./categories";

export interface BenchmarkExpectation {
  /** テストケース名（拡張子なし。例: "BenchmarkTest00001"） */
  name: string;
  category: BenchmarkCategory;
  /** true = 実際に脆弱（検出すべき）/ false = 安全な変種（検出したら FP） */
  isReal: boolean;
  /** CSV の cwe 列（数値化。無ければ null） */
  cwe: number | null;
}

export interface ParseResult {
  expectations: BenchmarkExpectation[];
  /** 解釈できず skip した行数（未知カテゴリ・列不足等）。silent に隠さず可視化する。 */
  skipped: number;
}

/** expectedresults CSV 本文をパースする。 */
export function parseExpectedResults(csv: string): ParseResult {
  const out: BenchmarkExpectation[] = [];
  let skipped = 0;

  const lines = csv.split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;                        // 空行
    if (line.startsWith("#")) continue;         // ヘッダ/コメント
    // ヘッダを # 無しで書く版もあるため、先頭が "test name" 系なら skip
    if (/^test\s*name\b/i.test(line)) continue;

    const cols = line.split(",").map((c) => c.trim());
    if (cols.length < 3) { skipped++; continue; }

    const [name, categoryRaw, realRaw, cweRaw] = cols;
    const category = categoryRaw.toLowerCase();
    if (!name || !isBenchmarkCategory(category)) { skipped++; continue; }

    const realLc = (realRaw ?? "").toLowerCase();
    const isReal = realLc === "true" || realLc === "1" || realLc === "yes";
    // 明示的に false/0/no でも true でもない値は安全側（false）に倒さず skip（曖昧を混ぜない）
    if (!(isReal || realLc === "false" || realLc === "0" || realLc === "no")) { skipped++; continue; }

    out.push({ name, category, isReal, cwe: parseCweNumber(cweRaw) });
  }

  return { expectations: out, skipped };
}
