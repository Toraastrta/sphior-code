/**
 * sca-benchmark.ts — SCA(依存脆弱性)検出精度の採点（PLAN Phase 0 / P0-4・純関数）
 *
 * SAST(benchmark)・DAST(dast-benchmark) と同じ測定規律を SCA にも適用する。
 * 「既知脆弱 lockfile を固定基準」にし、版マッチ境界（脆弱版=検出すべき / 修正版=検出したら FP）を測る。
 * 正解は (ecosystem, package, version, isReal) で与え、エンジン(Trivy/自前 SCA)が報告した依存と
 * 版まで含めて突き合わせる。採点の数理は identity-score(混同行列) を再利用し、実スキャン(要 lockfile)と
 * 分離してテストできる。
 *
 * 版を照合キーに含めるのが要点: 同じ package の脆弱版と修正版は別ケースになり、
 * 修正版を誤って報告すれば FP、脆弱版を取りこぼせば FN として正しく計上される。
 */

import { scoreIdentity, type IdentityCase, type GroupedScore } from "./identity-score";

/** 既知脆弱 lockfile の 1 依存に対する正解ラベル。 */
export interface ScaExpectation {
  /** パッケージ生態系（例 "npm" | "pypi" | "gomod"。Trivy の Result.Type に相当）。集計群にも使う。 */
  ecosystem: string;
  /** パッケージ名。 */
  pkg: string;
  /** 導入版（この版が脆弱か否かを isReal で表す）。 */
  version: string;
  /** true = この版が真に脆弱（検出すべき）/ false = 修正版など安全（検出したら FP）。 */
  isReal: boolean;
  /** 参考: 対応 CVE（照合キーには使わず、版境界を主軸にする）。 */
  cve?: string;
}

/** エンジンが「脆弱」と報告した依存の最小形（版まで持てば採点できる）。 */
export interface ScaFindingForScore {
  ecosystem?: string | null;
  pkg: string;
  version: string;
}

/** 照合キー: ecosystem:pkg@version（大小・空白を正規化して取りこぼしを防ぐ）。 */
export function scaKey(ecosystem: string | null | undefined, pkg: string, version: string): string {
  return `${(ecosystem ?? "").trim().toLowerCase()}:${pkg.trim().toLowerCase()}@${version.trim()}`;
}

/** 正解(既知脆弱 lockfile) + エンジン報告 → ecosystem 群別/全体スコア。 */
export function scoreSca(
  expectations: ScaExpectation[],
  findings: ScaFindingForScore[],
): GroupedScore {
  const reported = new Set(findings.map((f) => scaKey(f.ecosystem, f.pkg, f.version)));
  const cases: IdentityCase[] = expectations.map((e) => ({
    key: scaKey(e.ecosystem, e.pkg, e.version),
    group: (e.ecosystem || "unknown").trim().toLowerCase(),
    isReal: e.isReal,
  }));
  return scoreIdentity(cases, reported);
}
