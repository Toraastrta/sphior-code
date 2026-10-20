/**
 * suppress.ts — 除外と抑制（設計 §4.1・ノイズ対策の正本）
 *
 * ## なぜ 2 つの概念に分けるか
 * 「見なかった」と「見たうえで受け入れた」を同じ箱に入れない。これを混ぜると
 * 「0 件でした」が何を意味するのか分からなくなる（cli.ts が 0 件走査を緑にしない
 * のと同じ原則）。
 *
 *   - **除外 (exclude)**: そのファイルを走査しない。ビルド出力・ベンダ等。
 *     → findings は生まれない。代わりに「何件のファイルを除外したか」を残す。
 *   - **抑制 (suppress)**: 走査して検出し、そのうえで受け入れた判断を記録する。
 *     テストベクタ・ルール表そのもの・意図した固定入力等。
 *     → finding は消さず `suppression` を付けて `suppressed` に分ける。
 *
 * ## 2 つの入口
 *   1. `.sphiorignore`（走査ルート直下）
 *        Docs/**                                    ← 除外（ルール指定なし）
 *        src/lib/scan/patterns/rules.ts  pattern.*  ← 抑制（ルール限定）
 *        path  rule  # 理由                          ← 末尾 # は justification
 *   2. ソース中のインラインコメント
 *        eval(s); // sphior-ignore: 固定入力しか来ない
 *        // sphior-ignore-next-line secret.private_key: 説明用のヘッダ文字列
 *
 * ## 設計上の約束
 *   - **SARIF には抑制分を載せない**。GitHub Code scanning は SARIF の
 *     `result.suppressions` を解釈せず（公式ドキュメントの supported properties に
 *     存在しない）、載せると「抑制したはずの finding が普通の open アラートとして
 *     並ぶ」逆効果になる。抑制の事実は `--json` と証跡側に残す。
 *   - glob は正規表現へ安全に変換する（ユーザー入力をそのまま RegExp にしない）。
 *   - 解釈できない行は黙って捨てず `problems` に残す（効いているつもりの設定を作らない）。
 */

import type { CanonicalFinding } from "./types";

/** `.sphiorignore` の 1 行。由来を人に戻せるよう行番号を保持する。 */
export interface SuppressEntry {
  /** `.sphiorignore` 内の行番号（1-based）。 */
  line: number;
  /** パス glob（走査ルート相対・POSIX 区切り）。 */
  glob: string;
  /** ルール id（末尾 `*` で前方一致）。未指定ならファイルごと除外。 */
  ruleId?: string;
  /** 末尾 `# ...` に書かれた理由。 */
  justification?: string;
}

export interface SphiorignoreConfig {
  /** ルール指定なし = ファイルごと除外（走査しない）。 */
  excludes: SuppressEntry[];
  /** ルール指定あり = 走査はして、当該ルールだけ抑制する。 */
  scoped: SuppressEntry[];
  /** 解釈できなかった行（効いていない設定を黙らせないため）。 */
  problems: Array<{ line: number; text: string; reason: string }>;
}

export const EMPTY_CONFIG: SphiorignoreConfig = { excludes: [], scoped: [], problems: [] };

/** `.sphiorignore` の既定ファイル名（走査ルート直下）。 */
export const SPHIORIGNORE_FILE = ".sphiorignore";

// ── glob ────────────────────────────────────────────────────────────────────

/** 正規表現メタ文字を潰す（glob 由来の `*` `?` は後段で戻す）。 */
function escapeRe(s: string): string {
  return s.replace(/[.+^$(){}|[\]\\]/g, "\\$&");
}

/**
 * glob → 行頭行末アンカー付き RegExp。
 * 二連アスタリスクは階層跨ぎ、`*` `?` は単一階層内。二連アスタリスク＋スラッシュは
 * 0 階層にもマッチさせる（配下指定がルート直下にも当たるようにするため）。
 */
export function globToRegExp(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // `**/` は「0 個以上の階層」。末尾 `**` は残り全部
        if (glob[i + 2] === "/") {
          out += "(?:[^/]+/)*";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else {
        out += "[^/]*";
      }
      continue;
    }
    if (c === "?") {
      out += "[^/]";
      continue;
    }
    out += escapeRe(c);
  }
  return new RegExp(`^${out}$`);
}

/**
 * glob がパスに当たるか。
 * ワイルドカードを持たない glob は「そのパス自身」と「その配下」の両方に当たる
 * （`Docs` と書いて `Docs/a/b.md` が外れる、という驚きを作らないため）。
 */
export function globMatches(glob: string, relPath: string): boolean {
  const g = glob.endsWith("/") ? `${glob.slice(0, -1)}` : glob;
  if (globToRegExp(g).test(relPath)) return true;
  return globToRegExp(`${g}/**`).test(relPath);
}

/** ルール id の一致（末尾 `*` で前方一致）。 */
export function ruleMatches(pattern: string, ruleId: string): boolean {
  if (pattern.endsWith("*")) return ruleId.startsWith(pattern.slice(0, -1));
  return pattern === ruleId;
}

// ── .sphiorignore ───────────────────────────────────────────────────────────

/** ルール id として妥当か（パス glob と見分けるため・`/` を含まない） */
function looksLikeRuleId(tok: string): boolean {
  return /^[A-Za-z][A-Za-z0-9_.-]*\*?$/.test(tok) && !tok.includes("/");
}

/**
 * `.sphiorignore` を解析する。純関数（ファイル読み込みは collect.ts 側）。
 *
 * 1 行の形: `<glob> [rule_id] [# 理由]`
 * 空行と `#` 始まりはコメント。
 */
export function parseSphiorignore(text: string): SphiorignoreConfig {
  const excludes: SuppressEntry[] = [];
  const scoped: SuppressEntry[] = [];
  const problems: SphiorignoreConfig["problems"] = [];

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const lineNo = i + 1;
    if (!raw.trim() || raw.trim().startsWith("#")) continue;

    // 末尾 `# ...` は理由。パスに `#` は使えないが、gitignore も同じ制約なので揃える
    const hashAt = raw.indexOf("#");
    const body = (hashAt >= 0 ? raw.slice(0, hashAt) : raw).trim();
    const justification = hashAt >= 0 ? raw.slice(hashAt + 1).trim() || undefined : undefined;
    if (!body) continue;

    const tokens = body.split(/\s+/);
    if (tokens.length > 2) {
      problems.push({ line: lineNo, text: body, reason: "expected `<glob> [rule_id]` (too many fields)" });
      continue;
    }
    const [glob, ruleId] = tokens;
    if (glob.startsWith("/")) {
      problems.push({ line: lineNo, text: body, reason: "paths are relative to the scan root — drop the leading `/`" });
      continue;
    }
    if (ruleId !== undefined && !looksLikeRuleId(ruleId)) {
      problems.push({ line: lineNo, text: body, reason: `not a rule id: ${ruleId}` });
      continue;
    }
    const entry: SuppressEntry = { line: lineNo, glob, ruleId, justification };
    (ruleId === undefined ? excludes : scoped).push(entry);
  }

  return { excludes, scoped, problems };
}

/**
 * 除外判定器を作る。collect.ts の walk に渡してファイルを読む前に落とす。
 * 呼び出し回数を数えたい側（CLI のサマリ）は自前のクロージャで包む。
 */
export function makePathExcluder(cfg: SphiorignoreConfig): (relPath: string) => boolean {
  if (cfg.excludes.length === 0) return () => false;
  return (relPath) => cfg.excludes.some((e) => globMatches(e.glob, relPath));
}

/** 設定由来の抑制（path × rule）を引く。 */
export function configSuppressionFor(
  cfg: SphiorignoreConfig,
  path: string,
  ruleId: string,
): SuppressEntry | undefined {
  return cfg.scoped.find((e) => e.ruleId && ruleMatches(e.ruleId, ruleId) && globMatches(e.glob, path));
}

// ── インラインコメント ──────────────────────────────────────────────────────

/**
 * `sphior-ignore` / `sphior-ignore-next-line` を 1 行から読む。
 * 言語ごとのコメント記法に踏み込まない（`#` `//` `--` `;` `*` いずれでも拾う）。
 * ルール id と理由はどちらも省略できる。
 */
const INLINE_RE = /sphior-ignore(-next-line)?(?:[ \t]+([A-Za-z][A-Za-z0-9_.-]*\*?))?(?:[ \t]*:[ \t]*(.*))?$/;

export interface InlineSuppression {
  /** 指定されていればそのルールだけ、無ければその行の全 finding。 */
  ruleId?: string;
  justification?: string;
  /** `-next-line` 形式か。 */
  nextLine: boolean;
}

export function parseInlineSuppression(lineText: string): InlineSuppression | undefined {
  const m = INLINE_RE.exec(lineText);
  if (!m) return undefined;
  return {
    nextLine: m[1] === "-next-line",
    ruleId: m[2],
    justification: m[3]?.trim() || undefined,
  };
}

/**
 * finding の行に効くインライン抑制を引く。
 * 当該行の行末コメント（`sphior-ignore`）と、直前行の `sphior-ignore-next-line` を見る。
 */
export function inlineSuppressionFor(
  lines: string[],
  startLine: number,
  ruleId: string,
): InlineSuppression | undefined {
  const own = lines[startLine - 1] !== undefined ? parseInlineSuppression(lines[startLine - 1]) : undefined;
  if (own && !own.nextLine && (!own.ruleId || ruleMatches(own.ruleId, ruleId))) return own;

  const prev = startLine >= 2 && lines[startLine - 2] !== undefined ? parseInlineSuppression(lines[startLine - 2]) : undefined;
  if (prev && prev.nextLine && (!prev.ruleId || ruleMatches(prev.ruleId, ruleId))) return prev;

  return undefined;
}

// ── 適用 ────────────────────────────────────────────────────────────────────

export interface ApplySuppressionsInput {
  config?: SphiorignoreConfig;
  /** path → 本文。インライン抑制の読み取りに使う（無ければ設定由来のみ）。 */
  textByPath?: Map<string, string>;
}

export interface SuppressionSplit {
  /** 抑制されなかった finding。既存の `findings` と同じ意味を保つ。 */
  active: CanonicalFinding[];
  /** 検出したが抑制した finding（`suppression` 付き）。 */
  suppressed: CanonicalFinding[];
}

/**
 * findings を active / suppressed に分ける。入力順を保持（決定論）。
 * 入力は変更しない（抑制分は `suppression` を足した複製を返す）。
 */
export function applySuppressions(
  findings: CanonicalFinding[],
  input: ApplySuppressionsInput = {},
): SuppressionSplit {
  const cfg = input.config;
  const hasConfig = !!cfg && cfg.scoped.length > 0;
  const hasText = !!input.textByPath && input.textByPath.size > 0;
  if (!hasConfig && !hasText) return { active: findings, suppressed: [] };

  // 行配列はファイル単位でキャッシュ（finding ごとに split し直さない）
  const linesCache = new Map<string, string[]>();
  const linesOf = (path: string): string[] | undefined => {
    const cached = linesCache.get(path);
    if (cached) return cached;
    const text = input.textByPath?.get(path);
    if (text === undefined) return undefined;
    const lines = text.split(/\r?\n/);
    linesCache.set(path, lines);
    return lines;
  };

  const active: CanonicalFinding[] = [];
  const suppressed: CanonicalFinding[] = [];

  for (const f of findings) {
    const byConfig = hasConfig ? configSuppressionFor(cfg, f.location.path, f.rule_id) : undefined;
    if (byConfig) {
      suppressed.push({
        ...f,
        suppression: {
          by: "config",
          rule_scoped: true,
          justification: byConfig.justification,
          source: `${SPHIORIGNORE_FILE}:${byConfig.line}`,
        },
      });
      continue;
    }

    const lines = linesOf(f.location.path);
    const byInline = lines ? inlineSuppressionFor(lines, f.location.start_line, f.rule_id) : undefined;
    if (byInline) {
      suppressed.push({
        ...f,
        suppression: {
          by: "inline",
          rule_scoped: !!byInline.ruleId,
          justification: byInline.justification,
          source: `${f.location.path}:${byInline.nextLine ? f.location.start_line - 1 : f.location.start_line}`,
        },
      });
      continue;
    }

    active.push(f);
  }

  return { active, suppressed };
}

/** 理由の書かれていない抑制の数（サマリで促すため・落とさない）。 */
export function countWithoutJustification(suppressed: CanonicalFinding[]): number {
  return suppressed.reduce((n, f) => (f.suppression && !f.suppression.justification ? n + 1 : n), 0);
}
