/**
 * chain.ts — hash-chain 検証（改ざん・断裂の独立検出・設計 §4.5 / §7）
 *
 * repo ごとに時系列で並んだ EvidenceRecord 群を検証：
 *  1) 各 record_hash が本体から再計算した値と一致（レコード改変検知）
 *  2) prev_record_hash が直前レコードの record_hash と一致（連鎖の断裂検知）
 * インスタンスにアクセスせず、監査人がオフラインで実行できる。
 */

import type { EvidenceRecord } from "./record";
import { recomputeRecordHash } from "./record";

export interface ChainVerifyResult {
  ok: boolean;
  /** 問題があった index（0-based）。ok なら undefined。 */
  brokenAt?: number;
  reason?: "record_hash_mismatch" | "chain_link_mismatch";
}

/** records は時系列昇順（古い→新しい）であること。 */
export function verifyChain(records: EvidenceRecord[]): ChainVerifyResult {
  let prevHash: string | null = null;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (recomputeRecordHash(r) !== r.record_hash) {
      return { ok: false, brokenAt: i, reason: "record_hash_mismatch" };
    }
    if (r.prev_record_hash !== prevHash) {
      return { ok: false, brokenAt: i, reason: "chain_link_mismatch" };
    }
    prevHash = r.record_hash;
  }
  return { ok: true };
}
