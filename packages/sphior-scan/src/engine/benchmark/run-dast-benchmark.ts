/**
 * run-dast-benchmark.ts — DAST 検出を採点する実走オーケストレータ（P0-3 の実行部）
 *
 * ⚠️ server/CLI 専用（node:fs を使う）。クライアントバンドルから import しないこと。
 *
 * 手順:
 *   1. 脆弱アプリ（WAVSEP / Juice Shop / OWASP Benchmark web）のコーパス dir から
 *      expectations.json（BenchmarkExpectation[]。name=対象 URL・category・isReal）を読む。
 *   2. findings.json（DastFindingForScore[]。{url, cwe}）を読む。
 *   3. URL×CWE で正解と突き合わせて採点（dast-benchmark.ts / score.ts）。
 *
 * エンジン実行境界: DAST エンジン（ZAP/Nuclei）は外部ランナーで、対象を実スキャンして findings.json を
 * 吐く（proof-based と同じく「立てるだけ」）。本ドライバは「正解 × 出力の採点」を所有し、
 * 決定論・オフラインでテストできる。コーパスはリポジトリに含めない。DAST_BENCH_DIR で外部を指す。
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { scoreDast, type DastFindingForScore } from "./dast-benchmark";
import type { BenchmarkExpectation } from "./expected-results";
import type { BenchmarkScore } from "./score";

export interface RunDastBenchmarkOptions {
  /** コーパスのルート（expectations.json と findings.json を含む）。 */
  dir: string;
}

export interface RunDastBenchmarkResult {
  score: BenchmarkScore;
  /** 採点に用いた正解ケース数。 */
  cases: number;
  /** ランナーが報告した finding 数。 */
  findingsRead: number;
}

/** コーパス（正解 + ランナー出力）を読み、採点する。 */
export function runDastBenchmark(opts: RunDastBenchmarkOptions): RunDastBenchmarkResult {
  const expPath = join(opts.dir, "expectations.json");
  const findPath = join(opts.dir, "findings.json");
  if (!existsSync(expPath)) throw new Error(`expectations.json not found under ${opts.dir}`);
  if (!existsSync(findPath)) throw new Error(`findings.json not found under ${opts.dir}`);

  const expectations = JSON.parse(readFileSync(expPath, "utf8")) as BenchmarkExpectation[];
  const findings = JSON.parse(readFileSync(findPath, "utf8")) as DastFindingForScore[];

  return { score: scoreDast(expectations, findings), cases: expectations.length, findingsRead: findings.length };
}
