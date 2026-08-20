/**
 * identity-score.ts — 同一性照合ベースの混同行列採点（測定パイプライン・純関数・P0-4/P0-5）
 *
 * OWASP Benchmark(CWE カテゴリ)採点(score.ts)は SAST/DAST 用で「そのカテゴリの CWE を報告したか」で測る。
 * 一方 SCA/IaC は「特定の脆弱依存(版)を当てたか」「特定の誤設定(ルール×リソース)を当てたか」という
 * 安定キーの同一性で測るのが自然（CWE カテゴリでは版境界や個別ルールを表現できない）。
 *
 * 混同行列の数理は score.ts の metricsOf を再利用し、指標定義（TPR/FPR/precision/F1/Youden）を単一化する。
 * 群(group)は動的な文字列（SCA=ecosystem / IaC=provider 等）で、カテゴリ enum に縛られない。
 * 純関数・I/O なし・決定論（同入力→同出力・群は昇順ソート）。数値を捏造しない（分母 0 は null）。
 */

import { metricsOf, type Metrics, type ConfusionMatrix } from "./score";

/** 1 テストケース: 安定キー + 集計群 + 正解ラベル。 */
export interface IdentityCase {
  /** 照合の安定キー（例 SCA "npm:lodash@4.17.20" / IaC "AVD-AWS-0086@main.tf:12"）。 */
  key: string;
  /** 集計群（例 SCA ecosystem "npm" / IaC provider "aws"）。 */
  group: string;
  /** true = 真に脆弱（検出すべき）/ false = 安全変種（検出したら FP）。 */
  isReal: boolean;
}

export interface GroupedScore {
  /** 群別指標（テストケースが存在する群のみ・昇順）。 */
  perGroup: Record<string, Metrics>;
  /** 全群合算。 */
  overall: Metrics;
  /** TP を 1 度も出せていない群（= 現状未カバー・検知漏れの温床）。 */
  uncoveredGroups: string[];
}

/**
 * 観測（正解ケース列 + エンジンが報告したキー集合）→ 群別 + 全体スコア。
 *   isReal かつ 報告あり → TP / isReal かつ 報告なし → FN
 *  !isReal かつ 報告あり → FP / !isReal かつ 報告なし → TN
 * @param cases 正解ケース群（キー・群・isReal）
 * @param reportedKeys エンジンが「検出」として報告したキーの集合（配列/Set いずれも可）
 */
export function scoreIdentity(cases: IdentityCase[], reportedKeys: Iterable<string>): GroupedScore {
  const reported = reportedKeys instanceof Set ? (reportedKeys as Set<string>) : new Set(reportedKeys);

  const cms = new Map<string, ConfusionMatrix>();
  const everDetected = new Set<string>();
  const ensure = (g: string): ConfusionMatrix => {
    let cm = cms.get(g);
    if (!cm) { cm = { tp: 0, fp: 0, fn: 0, tn: 0 }; cms.set(g, cm); }
    return cm;
  };

  for (const c of cases) {
    const cm = ensure(c.group);
    const detected = reported.has(c.key);
    if (detected) everDetected.add(c.group);
    if (c.isReal) {
      if (detected) cm.tp++; else cm.fn++;
    } else {
      if (detected) cm.fp++; else cm.tn++;
    }
  }

  const groups = [...cms.keys()].sort();
  const perGroup: Record<string, Metrics> = {};
  const total: ConfusionMatrix = { tp: 0, fp: 0, fn: 0, tn: 0 };
  const uncoveredGroups: string[] = [];

  for (const g of groups) {
    const cm = cms.get(g)!;
    perGroup[g] = metricsOf(cm);
    total.tp += cm.tp; total.fp += cm.fp; total.fn += cm.fn; total.tn += cm.tn;
    if (!everDetected.has(g) && (cm.tp + cm.fn) > 0) uncoveredGroups.push(g);
  }

  return { perGroup, overall: metricsOf(total), uncoveredGroups };
}
