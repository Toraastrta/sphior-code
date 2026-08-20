/**
 * run-benchmark.ts — 実 OWASP Benchmark を本番エンジンに噛ませる測定オーケストレータ（M4）
 *
 * ⚠️ server/CLI 専用（node:fs を使う）。クライアントバンドルから import しないこと。
 *
 * 手順:
 *   1. Benchmark チェックアウト dir から expectedresults CSV を読む。
 *   2. 各テストケース <name>.java を testcase ディレクトリから読み、本番 SaaS エンジン runScan に通す。
 *   3. finding の CWE をカテゴリへ写像し、正解と突き合わせて採点（score.ts）。
 *
 * Benchmark はリポジトリに含めない。BENCHMARK_DIR で外部チェックアウトを指す（README 参照）。
 */

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { runScan } from "../run";
import { ENGINE_VERSION, RULESET_VERSION } from "../version";
import { parseExpectedResults } from "./expected-results";
import { scoreBenchmark, type CaseObservation, type BenchmarkScore } from "./score";

export interface RunBenchmarkOptions {
  /** Benchmark チェックアウトのルート（BenchmarkJava 等）。 */
  benchmarkDir: string;
  /** expectedresults CSV への明示パス（省略時はルート直下を自動探索）。 */
  expectedCsvPath?: string;
  /** testcase の .java があるディレクトリ（省略時は標準レイアウトを自動探索）。 */
  testcaseDir?: string;
}

export interface RunBenchmarkResult {
  engineVersion: string;
  rulesetVersion: string;
  score: BenchmarkScore;
  /** 解釈できた総テストケース数。 */
  cases: number;
  /** .java が見つからず測定できなかったケース数（可視化する）。 */
  missingFiles: number;
  /** CSV パース時に skip した行数。 */
  skippedRows: number;
}

// 標準レイアウト。新しい版は testcase/、v1.2 系は testcode/ を使う。
const TESTCASE_RELS = [
  join("src", "main", "java", "org", "owasp", "benchmark", "testcase"),
  join("src", "main", "java", "org", "owasp", "benchmark", "testcode"),
];

/** ルート直下から expectedresults*.csv を探す。 */
function findExpectedCsv(dir: string, explicit?: string): string {
  if (explicit) {
    if (!existsSync(explicit)) throw new Error(`expectedresults CSV not found: ${explicit}`);
    return explicit;
  }
  const entries = existsSync(dir) ? readdirSync(dir) : [];
  const csv = entries
    .filter((f) => /^expectedresults.*\.csv$/i.test(f))
    .sort()           // 複数版があれば決定論的に最後（新しい版名）を採る
    .pop();
  if (!csv) throw new Error(`expectedresults CSV not found under ${dir}`);
  return join(dir, csv);
}

/** testcase ディレクトリを決める（明示 > 標準レイアウト testcase|testcode）。 */
function resolveTestcaseDir(dir: string, explicit?: string): string {
  if (explicit) return explicit;
  for (const rel of TESTCASE_RELS) {
    const p = join(dir, rel);
    if (existsSync(p)) return p;
  }
  throw new Error(`testcase dir not found (looked for ${TESTCASE_RELS.join(" , ")}). Pass testcaseDir explicitly.`);
}

/** 実 Benchmark を走査して採点する。 */
export function runBenchmark(opts: RunBenchmarkOptions): RunBenchmarkResult {
  const csvPath = findExpectedCsv(opts.benchmarkDir, opts.expectedCsvPath);
  const testcaseDir = resolveTestcaseDir(opts.benchmarkDir, opts.testcaseDir);

  const { expectations, skipped } = parseExpectedResults(readFileSync(csvPath, "utf8"));

  const observations: CaseObservation[] = [];
  let missingFiles = 0;

  for (const exp of expectations) {
    const javaPath = join(testcaseDir, `${exp.name}.java`);
    if (!existsSync(javaPath)) { missingFiles++; continue; }
    const text = readFileSync(javaPath, "utf8");

    // 本番 SaaS エンジンでスキャン（PR ゲート等の後段フィルタは通さず raw finding で測る）。
    const { findings } = runScan({ files: [{ path: `${exp.name}.java`, text }] });
    observations.push({
      expectation: exp,
      reportedCwes: findings.map((f) => f.cwe ?? null),
    });
  }

  return {
    engineVersion: ENGINE_VERSION,
    rulesetVersion: RULESET_VERSION,
    score: scoreBenchmark(observations),
    cases: observations.length,
    missingFiles,
    skippedRows: skipped,
  };
}
