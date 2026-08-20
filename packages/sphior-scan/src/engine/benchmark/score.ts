/**
 * score.ts — 混同行列と精度指標の算出（測定パイプライン M3・純関数）
 *
 * OWASP Benchmark 公式方法論に準拠して、カテゴリ毎に独立して採点する:
 *   あるカテゴリ C のテストケース群のみを使い、そのケースで「C の CWE を報告したか」を判定する。
 *     - isReal かつ 検出          → TP（真陽性）
 *     - isReal かつ 未検出        → FN（偽陰性 = 検知漏れ）
 *     - !isReal かつ 検出         → FP（偽陽性 = 誤検知）
 *     - !isReal かつ 未検出       → TN（真陰性）
 *
 * 指標:
 *   TPR (recall/sensitivity) = TP / (TP + FN)
 *   FPR (fall-out)           = FP / (FP + TN)
 *   precision                = TP / (TP + FP)
 *   F1                       = 2·precision·recall / (precision + recall)
 *   Youden J（= Benchmark スコア） = TPR − FPR
 * 分母 0 は null（"—" 表示）。数値を捏造しない。
 *
 * この関数は I/O を持たない。実ファイル走査は run-benchmark.ts が担う。
 */

import { detectedCategories, BENCHMARK_CATEGORIES, type BenchmarkCategory } from "./categories";
import type { BenchmarkExpectation } from "./expected-results";

/** 1 テストケースの測定入力: 正解 + そのファイルでエンジンが出した CWE 群。 */
export interface CaseObservation {
  expectation: BenchmarkExpectation;
  /** 当該ファイルに対しエンジンが報告した finding の CWE 群（"CWE-89" | 89 いずれも可）。 */
  reportedCwes: Array<string | number | null | undefined>;
}

export interface ConfusionMatrix {
  tp: number; fp: number; fn: number; tn: number;
}

export interface Metrics extends ConfusionMatrix {
  total: number;
  /** 真陽性率（検知できた割合）。分母 0 は null。 */
  tpr: number | null;
  /** 偽陽性率（安全変種を誤検知した割合）。分母 0 は null。 */
  fpr: number | null;
  precision: number | null;
  f1: number | null;
  /** Youden J = TPR − FPR（OWASP Benchmark スコア）。両率が出る時のみ。 */
  youden: number | null;
}

export interface BenchmarkScore {
  /** カテゴリ別指標（テストケースが存在するカテゴリのみ）。 */
  perCategory: Partial<Record<BenchmarkCategory, Metrics>>;
  /** 全カテゴリ合算。 */
  overall: Metrics;
  /** エンジンが命中扱いできた CWE を 1 つも持たないカテゴリ（= 現状未カバー）。 */
  uncoveredCategories: BenchmarkCategory[];
}

/** 混同行列 → 指標。SCA/IaC の同一性採点(identity-score.ts)も同じ数理を再利用する（指標定義を単一化）。 */
export function metricsOf(cm: ConfusionMatrix): Metrics {
  const { tp, fp, fn, tn } = cm;
  const tpr = tp + fn > 0 ? tp / (tp + fn) : null;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : null;
  const precision = tp + fp > 0 ? tp / (tp + fp) : null;
  const f1 =
    precision != null && tpr != null && precision + tpr > 0
      ? (2 * precision * tpr) / (precision + tpr)
      : null;
  const youden = tpr != null && fpr != null ? tpr - fpr : null;
  return { tp, fp, fn, tn, total: tp + fp + fn + tn, tpr, fpr, precision, f1, youden };
}

/**
 * 観測列 → カテゴリ別 + 全体スコア。
 * 各ケースは自身のカテゴリの混同行列にのみ寄与する（他カテゴリの検出は無視 = 公式方法論）。
 */
export function scoreBenchmark(observations: CaseObservation[]): BenchmarkScore {
  const cms = new Map<BenchmarkCategory, ConfusionMatrix>();
  const ensure = (c: BenchmarkCategory): ConfusionMatrix => {
    let cm = cms.get(c);
    if (!cm) { cm = { tp: 0, fp: 0, fn: 0, tn: 0 }; cms.set(c, cm); }
    return cm;
  };
  /** 実際に検出できたカテゴリ（uncovered 判定用）。 */
  const everDetected = new Set<BenchmarkCategory>();

  for (const obs of observations) {
    const cat = obs.expectation.category;
    const cm = ensure(cat);
    const hits = detectedCategories(obs.reportedCwes);
    const detected = hits.has(cat);
    if (detected) everDetected.add(cat);

    if (obs.expectation.isReal) {
      if (detected) cm.tp++; else cm.fn++;
    } else {
      if (detected) cm.fp++; else cm.tn++;
    }
  }

  const perCategory: Partial<Record<BenchmarkCategory, Metrics>> = {};
  const total: ConfusionMatrix = { tp: 0, fp: 0, fn: 0, tn: 0 };
  const uncoveredCategories: BenchmarkCategory[] = [];

  for (const cat of BENCHMARK_CATEGORIES) {
    const cm = cms.get(cat);
    if (!cm) continue; // このカテゴリのテストケースが無い
    perCategory[cat] = metricsOf(cm);
    total.tp += cm.tp; total.fp += cm.fp; total.fn += cm.fn; total.tn += cm.tn;
    // テストケースはあるのに TP を 1 度も出せていない → 未カバー疑い（検知漏れの温床）
    if (!everDetected.has(cat) && (cm.tp + cm.fn) > 0) uncoveredCategories.push(cat);
  }

  return { perCategory, overall: metricsOf(total), uncoveredCategories };
}
