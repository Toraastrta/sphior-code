/**
 * scope.ts — 検査範囲と除外理由の記録（純関数）
 *
 * ## なぜ必要か
 * スキャンは必ず何かを見ていない。にもかかわらず記録に残るのは「何件見つけたか」
 * だけで、「**何件を見なかったか・なぜ見なかったか**」が残っていなかった。
 * 顧客に出る文面は `Scanned 15 files · 2 findings` で、同じリポジトリの
 * 残り数千ファイルが検査されていない事実がどこにも現れない。
 *
 * 監査で強いのは「包括的に検査しました」ではなく
 * 「**これを見て、これは見ていない。理由はこれ**」である（North Star の「空白の証明」）。
 * 既存の `collection_failure` 封緘と同じ系統で、こちらは取得断ではなく**設計上の範囲**を残す。
 *
 * ## 設計
 * - **`excluded` のキーは「その経路が数えている理由」だけ置く。**
 *   キーが無い = その経路では該当しない / 数えていない。0 = 数えて該当なし。
 *   両者を混同すると「確認していないこと」を「確認済みで 0 件」と誤読させる
 *   （`kev` の 3 値や SLA の NULL と同じ考え方）。
 * - **適用した上限を併記する。** 上限が分からないと、なぜ打ち切られたかを第三者が
 *   再導出できない（`cost_rates` / `sla_policy` と同じ理由）。
 * - **`complete` は打ち切りの有無だけを見る。** 顧客の除外設定やビルド出力の除外は
 *   意図された範囲なので不完全とは呼ばない。**上限で切られた場合のみ false**。
 * - 顧客面に出す文面では内部ラベル（`file_cap` 等）を使わず平文へ写す。
 */

/** 除外の理由。内部ラベル（顧客面にはそのまま出さない・`SCOPE_REASON_LABEL` で写す）。 */
export type ExclusionReason =
  /** ビルド出力・生成物・ロックファイル等の既定除外 */
  | "skip_pattern"
  /** 顧客自身の除外設定（除外グロブ / .sphiorignore） */
  | "user_excluded"
  /** 解析対象の言語に該当しない */
  | "unsupported_language"
  /** ファイルサイズ上限の超過 */
  | "size_exceeded"
  /** 1 回のスキャンのファイル数上限で切られた ← 唯一 complete=false にする理由 */
  | "file_cap"
  /** 取得に失敗した（API エラー・権限など） */
  | "fetch_failed"
  /** バイナリ */
  | "binary";

export const EXCLUSION_REASONS: readonly ExclusionReason[] = [
  "skip_pattern", "user_excluded", "unsupported_language",
  "size_exceeded", "file_cap", "fetch_failed", "binary",
] as const;

/** 顧客面の平文（内部ラベルを出さない）。check run / レポートで使う。 */
const SCOPE_REASON_LABEL: Record<ExclusionReason, string> = {
  skip_pattern:         "build output or generated files",
  user_excluded:        "excluded by your settings",
  unsupported_language: "file types not analyzed",
  size_exceeded:        "above the size limit",
  file_cap:             "beyond this scan's file limit",
  fetch_failed:         "could not be retrieved",
  binary:               "binary files",
};

export interface ScanScopeLimits {
  /** 1 ファイルのサイズ上限（バイト）。 */
  max_file_bytes: number;
  /** 1 回のスキャンのファイル数上限。上限なしなら null。 */
  max_files: number | null;
}

export interface ScanScope {
  /** 入口に並んだ総数（除外判定の前）。 */
  candidates: number;
  /** 実際に解析した数。 */
  examined: number;
  /**
   * 理由別の除外件数。**キーが無い = その経路では数えていない**（0 とは別の意味）。
   */
  excluded: Partial<Record<ExclusionReason, number>>;
  /** 解析した分の言語構成（拡張子由来の言語名 → 件数）。 */
  languages: Record<string, number>;
  /** 適用した上限。打ち切りの理由を第三者が再導出できるようにする。 */
  limits: ScanScopeLimits;
  /** examined / candidates（candidates=0 なら null。0% ではない）。小数 4 桁。 */
  coverage: number | null;
  /** 上限で切られていないか。顧客の除外やビルド出力の除外では false にしない。 */
  complete: boolean;
}

export interface ScanScopeInput {
  candidates: number;
  /** 解析したファイルの言語名。null/空は "unknown" に寄せる。 */
  examinedLanguages: Array<string | null | undefined>;
  /** 数えた理由だけを渡す（数えていない理由はキーごと渡さない）。 */
  excluded: Partial<Record<ExclusionReason, number>>;
  limits: ScanScopeLimits;
}

/** 検査範囲の記録を組み立てる（決定論・同入力同出力）。 */
export function buildScanScope(input: ScanScopeInput): ScanScope {
  const examined = input.examinedLanguages.length;

  // 言語構成（キー昇順で安定化 — ハッシュ封筒に入るため並びを固定する）
  const langCounts = new Map<string, number>();
  for (const raw of input.examinedLanguages) {
    const lang = raw && String(raw).trim() !== "" ? String(raw).trim() : "unknown";
    langCounts.set(lang, (langCounts.get(lang) ?? 0) + 1);
  }
  const languages: Record<string, number> = {};
  for (const k of [...langCounts.keys()].sort()) languages[k] = langCounts.get(k)!;

  // 除外件数（負値・非整数は 0 に寄せる。キー順は EXCLUSION_REASONS 固定）
  const excluded: Partial<Record<ExclusionReason, number>> = {};
  for (const reason of EXCLUSION_REASONS) {
    const v = input.excluded[reason];
    if (v === undefined) continue; // 数えていない理由はキーを作らない
    excluded[reason] = Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
  }

  const candidates = Number.isFinite(input.candidates) && input.candidates > 0
    ? Math.floor(input.candidates)
    : examined; // candidates 未提供なら examined を下限として扱う（coverage を 1 にする）

  return {
    candidates,
    examined,
    excluded,
    languages,
    limits: input.limits,
    coverage: candidates === 0 ? null : Math.round((examined / candidates) * 10_000) / 10_000,
    // 上限で切られたときだけ不完全。意図された除外は不完全と呼ばない。
    complete: (excluded.file_cap ?? 0) === 0,
  };
}

/**
 * 顧客面向けの 1 行要約（平文・内部ラベルを出さない）。
 *
 * 「全部見ました」と言わないのが要点。打ち切りがあれば**それを最初に述べる**。
 */
export function summarizeScope(scope: ScanScope): string {
  const n = (v: number) => v.toLocaleString("en-US");
  const parts: string[] = [`Examined ${n(scope.examined)} of ${n(scope.candidates)} files`];

  const notExamined = Math.max(0, scope.candidates - scope.examined);
  if (notExamined > 0) {
    // 件数の多い順。同数は理由の定義順で安定化（決定論）
    const order = new Map(EXCLUSION_REASONS.map((r, i) => [r, i]));
    const reasons = (Object.entries(scope.excluded) as Array<[ExclusionReason, number]>)
      .filter(([, v]) => v > 0)
      .sort((a, b) => b[1] - a[1] || order.get(a[0])! - order.get(b[0])!)
      .map(([r, v]) => `${SCOPE_REASON_LABEL[r]} ${n(v)}`);

    parts.push(reasons.length > 0
      ? `${n(notExamined)} not examined (${reasons.join(", ")})`
      : `${n(notExamined)} not examined`);
  }

  if (!scope.complete) {
    // ここが最も重要な一文。曖昧にしない。
    parts.push(`This scan did not cover the whole repository: its file limit of ${n(scope.limits.max_files ?? 0)} was reached`);
  }

  return parts.join(". ") + ".";
}
