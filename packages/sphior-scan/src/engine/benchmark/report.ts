/**
 * report.ts — 測定結果の整形（コンソール表 + JSON）（M4）
 *
 * 数値の主張は「実測値のみ」。分母 0 は "—"。overclaim（"合格"/"達成"）は使わない。
 */

import { BENCHMARK_CATEGORIES } from "./categories";
import type { Metrics } from "./score";
import type { RunBenchmarkResult } from "./run-benchmark";

function pct(v: number | null): string {
  return v == null ? "—" : `${(v * 100).toFixed(1)}%`;
}
function signed(v: number | null): string {
  return v == null ? "—" : `${v >= 0 ? "+" : ""}${(v * 100).toFixed(1)}`;
}
function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

const COLS: Array<{ h: string; w: number }> = [
  { h: "category", w: 14 }, { h: "TP", w: 5 }, { h: "FN", w: 5 }, { h: "FP", w: 5 }, { h: "TN", w: 5 },
  { h: "TPR", w: 8 }, { h: "FPR", w: 8 }, { h: "F1", w: 8 }, { h: "Youden", w: 8 },
];

function row(label: string, m: Metrics): string {
  const cells = [
    pad(label, COLS[0].w),
    pad(String(m.tp), COLS[1].w),
    pad(String(m.fn), COLS[2].w),
    pad(String(m.fp), COLS[3].w),
    pad(String(m.tn), COLS[4].w),
    pad(pct(m.tpr), COLS[5].w),
    pad(pct(m.fpr), COLS[6].w),
    pad(pct(m.f1), COLS[7].w),
    pad(signed(m.youden), COLS[8].w),
  ];
  return cells.join(" ");
}

/** 人間可読なコンソールレポートを組み立てる。 */
export function formatBenchmarkReport(res: RunBenchmarkResult): string {
  const lines: string[] = [];
  lines.push(`SPHIOR CODE SAST — OWASP Benchmark measurement`);
  lines.push(`engine ${res.engineVersion} / ruleset ${res.rulesetVersion}`);
  lines.push(`cases=${res.cases}  missingFiles=${res.missingFiles}  skippedRows=${res.skippedRows}`);
  lines.push("");
  lines.push(COLS.map((c) => pad(c.h, c.w)).join(" "));
  lines.push(COLS.map((c) => "-".repeat(c.w)).join(" "));

  for (const cat of BENCHMARK_CATEGORIES) {
    const m = res.score.perCategory[cat];
    if (m) lines.push(row(cat, m));
  }
  lines.push(COLS.map((c) => "-".repeat(c.w)).join(" "));
  lines.push(row("OVERALL", res.score.overall));
  lines.push("");
  lines.push(`Youden J (= TPR − FPR, ×100) は高いほど良い。FPR は低いほど良い。`);
  if (res.score.uncoveredCategories.length > 0) {
    lines.push(`未カバー（TP=0 のカテゴリ = 検知漏れの温床）: ${res.score.uncoveredCategories.join(", ")}`);
  }
  return lines.join("\n");
}

/** CI/保存用の素の JSON（実測値のみ）。 */
export function toBenchmarkJson(res: RunBenchmarkResult): string {
  return JSON.stringify(res, null, 2);
}
