/**
 * entropy.ts — Shannon エントロピー（汎用高エントロピー秘密検出の補助）
 */

/** 文字列の Shannon エントロピー（bits/char）。 */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  const n = s.length;
  for (const c of freq.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * 「埋めてください」の値か（誤検知抑制）。
 *
 * 実測で `"sk_live_YOUR_KEY_HERE"`（MCP 設定の記入例）や
 * `'sk_live_51H...hardcoded'`（修正例の Before コード）がエントロピー的には
 * 秘密に見えてしまい、本物の検出に混ざっていた。人間向けの目印が入っている
 * 値は秘密ではない。
 *
 * 本物を取りこぼす方向のリスクは無視できる（ランダムな base64 に "YOUR" 等が
 * 並ぶ確率は 10^-6 未満）。一方で `.example` という**ファイル名**は根拠にしない
 * ——実際にこのリポジトリの `.dev.vars.example` には本物の本番キーが入っていた。
 * 判断材料は常に値そのもの。
 */
const PLACEHOLDER_MARKERS = [
  "your", "here", "example", "sample", "placeholder", "dummy", "changeme", "change_me",
  "hardcoded", "redacted", "insert", "replace", "todo", "fixme", "xxxx", "...", "<", ">",
];

export function looksLikePlaceholder(s: string): boolean {
  const lower = s.toLowerCase();
  return PLACEHOLDER_MARKERS.some((m) => lower.includes(m));
}

/** base64/hex っぽい高エントロピー文字列か（誤検知抑制の粗フィルタ）。 */
export function looksHighEntropy(s: string, minLen = 16, minEntropy = 3.5): boolean {
  if (s.length < minLen) return false;
  if (!/^[A-Za-z0-9+/=_\-.]+$/.test(s)) return false;
  // 単調（全部同じ文字・連番）は除外
  if (/^(.)\1+$/.test(s)) return false;
  return shannonEntropy(s) >= minEntropy;
}
