/**
 * merkle.ts — findings 集合の Merkle root（改ざん検知の中核・設計 §4.5）
 *
 * finding を1つでも改変すると root が変わる → 証跡レコードに root を刻むことで
 * 「その時点の findings 集合」を暗号学的に固定できる。決定論（fingerprint 昇順）。
 */

import type { CanonicalFinding } from "../types";
import { canonicalHash, sha256 } from "../canonical";

/** 2ノード連結ハッシュ（順序保持）。 */
function hashPair(a: string, b: string): string {
  return sha256(`${a}${b}`);
}

/** findings → Merkle root（hex）。空集合は決定論的な空 root。 */
export function merkleRoot(findings: CanonicalFinding[]): string {
  if (findings.length === 0) return sha256("sphior-empty-merkle");
  // 葉 = 各 finding の canonical ハッシュ（全フィールドを内包）。fingerprint 昇順。
  let level = [...findings]
    .sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0))
    .map((f) => canonicalHash(f));

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left; // 奇数は最後を複製
      next.push(hashPair(left, right));
    }
    level = next;
  }
  return level[0];
}

/** severity 別カウント（決定論・レコードのメタ）。 */
export function countBySeverity(findings: CanonicalFinding[]): Record<CanonicalFinding["severity"], number> {
  const c: Record<CanonicalFinding["severity"], number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}
