/**
 * dast-corpus.ts — OWASP Benchmark(web) から DAST 実測用 expectations を生成する（P0-3 コーパス）
 *
 * ⚠️ server/CLI 専用（node:fs）。BenchmarkJava は SAST と同一コーパスを DAST でも流用できる
 * （稼働 web アプリを ZAP でスキャンする）。各テストの正確な URL は .java の @WebServlet 注釈から
 * 導く（推測しない・全 2740 件が `@WebServlet(value="/<cat>-NN/BenchmarkTestNNNNN")` を持つ）。
 *
 * 手順:
 *   1. generateDastCorpus({ benchmarkDir, baseUrl }) → expectations.json（name=完全 URL・category・isReal）
 *   2. BenchmarkJava をデプロイ → ZAP でスキャン → findings.json（DastFindingForScore[]）
 *   3. `DAST_BENCH_DIR=<dir> npm run measure:dast`
 */

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parseExpectedResults, type BenchmarkExpectation } from "./expected-results";

/** .java の @WebServlet(value="...") から servlet パスを抽出（純関数・テスト可能）。 */
export function extractServletPath(javaText: string): string | null {
  const m = javaText.match(/@WebServlet\(\s*(?:value\s*=\s*)?"([^"]+)"/);
  return m ? m[1] : null;
}

const TESTCASE_RELS = [
  join("src", "main", "java", "org", "owasp", "benchmark", "testcode"),
  join("src", "main", "java", "org", "owasp", "benchmark", "testcase"),
];

function findExpectedCsv(dir: string, explicit?: string): string {
  if (explicit) {
    if (!existsSync(explicit)) throw new Error(`expectedresults CSV not found: ${explicit}`);
    return explicit;
  }
  const entries = existsSync(dir) ? readdirSync(dir) : [];
  const csv = entries.filter((f) => /^expectedresults.*\.csv$/i.test(f)).sort().pop();
  if (!csv) throw new Error(`expectedresults CSV not found under ${dir}`);
  return join(dir, csv);
}

function resolveTestcaseDir(dir: string, explicit?: string): string {
  if (explicit) return explicit;
  for (const rel of TESTCASE_RELS) {
    const p = join(dir, rel);
    if (existsSync(p)) return p;
  }
  throw new Error(`testcase dir not found (looked for ${TESTCASE_RELS.join(" , ")}). Pass testcaseDir explicitly.`);
}

export interface GenerateDastCorpusOptions {
  /** BenchmarkJava チェックアウトのルート。 */
  benchmarkDir: string;
  /** 稼働アプリのルート URL（context path 込み）。例 "https://localhost:8443/benchmark"。 */
  baseUrl: string;
  expectedCsvPath?: string;
  testcaseDir?: string;
}

export interface DastCorpusResult {
  /** name=完全 URL の DAST 正解列（そのまま expectations.json に書ける）。 */
  expectations: BenchmarkExpectation[];
  /** .java or servlet パスが無く URL 化できなかった数（可視化・silent に隠さない）。 */
  missing: number;
}

/** BenchmarkJava から DAST 用 expectations を生成する（URL は @WebServlet 由来で厳密）。 */
export function generateDastCorpus(opts: GenerateDastCorpusOptions): DastCorpusResult {
  const csvPath = findExpectedCsv(opts.benchmarkDir, opts.expectedCsvPath);
  const testcaseDir = resolveTestcaseDir(opts.benchmarkDir, opts.testcaseDir);
  const { expectations } = parseExpectedResults(readFileSync(csvPath, "utf8"));
  const base = opts.baseUrl.replace(/\/+$/, "");

  const out: BenchmarkExpectation[] = [];
  let missing = 0;
  for (const e of expectations) {
    const javaPath = join(testcaseDir, `${e.name}.java`);
    if (!existsSync(javaPath)) { missing++; continue; }
    const servlet = extractServletPath(readFileSync(javaPath, "utf8"));
    if (!servlet) { missing++; continue; }
    const url = `${base}${servlet.startsWith("/") ? "" : "/"}${servlet}`;
    out.push({ ...e, name: url });
  }
  return { expectations: out, missing };
}
