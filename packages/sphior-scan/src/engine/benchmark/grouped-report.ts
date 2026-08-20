/**
 * grouped-report.ts — GroupedScore（SCA/IaC の群別採点）のコンソール整形（純関数）。
 * score.ts の BenchmarkScore を整形する report.ts と対をなす。数値は捏造せず null は "—"。
 */

import type { GroupedScore } from "./identity-score";
import type { Metrics } from "./score";

function pct(v: number | null): string {
  return v == null ? "—" : `${(v * 100).toFixed(1)}%`;
}

function row(label: string, m: Metrics): string {
  const cell = `${label.padEnd(16)} TP=${m.tp} FP=${m.fp} FN=${m.fn} TN=${m.tn}`;
  return `${cell.padEnd(44)} TPR=${pct(m.tpr).padStart(6)} FPR=${pct(m.fpr).padStart(6)} F1=${pct(m.f1).padStart(6)} J=${m.youden == null ? "—" : m.youden.toFixed(2)}`;
}

/** タイトル + 群別行 + 全体行 + 未カバー群 を 1 つの表に整形する。 */
export function formatGroupedReport(title: string, s: GroupedScore): string {
  const lines: string[] = [title, "─".repeat(title.length)];
  for (const [group, m] of Object.entries(s.perGroup)) lines.push(row(group, m));
  lines.push(row("OVERALL", s.overall));
  if (s.uncoveredGroups.length > 0) {
    lines.push(`uncovered (TP=0): ${s.uncoveredGroups.join(", ")}`);
  }
  return lines.join("\n");
}
