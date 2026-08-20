/**
 * dast-benchmark.ts — DAST 検出精度の採点（PLAN Phase 0 / P0-3・純関数）
 *
 * SAST(benchmark)・SCA(parse-precision) と同じ測定規律を DAST にも適用する。
 * WAVSEP / OWASP Benchmark web / Juice Shop 等の「URL ごとに正解ラベル(category, real)」を持つ
 * 脆弱アプリに対し、SPHIOR の DAST(ZAP+Nuclei) を回して得た findings を URL 単位で突き合わせ、
 * カテゴリ別 TPR/FPR を出す。採点器は純関数で、実スキャン(要ターゲット)と分離してテストできる。
 *
 * 採点は score.ts(scoreBenchmark) と categories.ts(CWE→category) を再利用する（指標定義を単一化）。
 */

import { scoreBenchmark, type CaseObservation, type BenchmarkScore } from "./score";
import type { BenchmarkExpectation } from "./expected-results";

/** DAST finding の最小形（URL と CWE を持てば採点できる）。 */
export interface DastFindingForScore {
  /** 検出された対象 URL（endpoint）。正解 URL と正規化して突合する。 */
  url: string;
  /** "CWE-89" | 89 いずれも可（null は無視）。 */
  cwe: string | number | null;
}

/** URL 正規化: スキーム/トレイリングスラッシュ/クエリ差を吸収して突合の取りこぼしを防ぐ。 */
export function normalizeUrl(u: string): string {
  try {
    const url = new URL(u);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    return `${url.host}${path}`; // host+path（scheme/query/fragment を落とす）
  } catch {
    return u.replace(/[?#].*$/, "").replace(/\/+$/, "");
  }
}

/**
 * 正解(URL ごとの expectation)と DAST findings を突き合わせ、scoreBenchmark 入力へ整形する。
 * expectation.name を「対象 URL」として解釈する（DAST の testcase は URL 単位のため）。
 */
export function dastToObservations(
  expectations: BenchmarkExpectation[],
  findings: DastFindingForScore[],
): CaseObservation[] {
  // URL(正規化) → CWE 群
  const byUrl = new Map<string, Array<string | number | null>>();
  for (const f of findings) {
    const key = normalizeUrl(f.url);
    const arr = byUrl.get(key) ?? [];
    arr.push(f.cwe);
    byUrl.set(key, arr);
  }
  return expectations.map((e) => ({
    expectation: e,
    reportedCwes: byUrl.get(normalizeUrl(e.name)) ?? [],
  }));
}

/** 正解 + findings → カテゴリ別/全体スコア。 */
export function scoreDast(
  expectations: BenchmarkExpectation[],
  findings: DastFindingForScore[],
): BenchmarkScore {
  return scoreBenchmark(dastToObservations(expectations, findings));
}
