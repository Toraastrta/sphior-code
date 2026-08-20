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

/** base64/hex っぽい高エントロピー文字列か（誤検知抑制の粗フィルタ）。 */
export function looksHighEntropy(s: string, minLen = 16, minEntropy = 3.5): boolean {
  if (s.length < minLen) return false;
  if (!/^[A-Za-z0-9+/=_\-.]+$/.test(s)) return false;
  // 単調（全部同じ文字・連番）は除外
  if (/^(.)\1+$/.test(s)) return false;
  return shannonEntropy(s) >= minEntropy;
}
