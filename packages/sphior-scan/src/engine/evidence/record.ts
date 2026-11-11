/**
 * record.ts — 証跡レコード生成（設計 §4.5）
 *
 * 1 権威スキャン = 1 EvidenceRecord。commit SHA に anchor し、repo ごとの
 * hash-chain（prev_record_hash）で追記専用・改ざん検知を成立させる。
 * record_hash = canonicalHash(record − record_hash)（自己参照を避けて確定）。
 */

import type { CanonicalFinding, Severity } from "../types";
import { canonicalHash } from "../canonical";
import { merkleRoot, countBySeverity } from "./merkle";
import type { ScanScope } from "../scope";

export interface EvidenceRecordInput {
  repo: string;
  branch: string;
  commit_sha: string;
  engine_version: string;
  ruleset_version: string;
  advisory_db_snapshot?: string;
  /** RFC3161 タイムスタンプトークン(base64) または ISO8601 フォールバック。 */
  scanned_at: string;
  actor: string;
  /** 直前レコードの record_hash（初回は null）。 */
  prev_record_hash: string | null;
  /**
   * 検査範囲と除外理由（`scope.ts`）。**ハッシュ封筒の中に入る**ので、
   * 「何を見て何を見なかったか」も findings と同じ強度で改竄検知できる。
   *
   * 後方互換: 省略時は `stabilize` が undefined キーを落とすため、
   * scope を持たない既存レコードの record_hash は**一切変わらない**
   * （record.test.ts で既知ハッシュを固定して守っている）。
   */
  scope?: ScanScope;
}

export interface EvidenceRecord extends EvidenceRecordInput {
  findings_merkle_root: string;
  finding_count: number;
  finding_count_by_severity: Record<Severity, number>;
  record_hash: string;
}

/** findings から EvidenceRecord を決定論的に生成。 */
export function buildEvidenceRecord(input: EvidenceRecordInput, findings: CanonicalFinding[]): EvidenceRecord {
  const body = {
    repo: input.repo,
    branch: input.branch,
    commit_sha: input.commit_sha,
    engine_version: input.engine_version,
    ruleset_version: input.ruleset_version,
    advisory_db_snapshot: input.advisory_db_snapshot,
    scanned_at: input.scanned_at,
    actor: input.actor,
    prev_record_hash: input.prev_record_hash,
    // 未指定なら undefined のまま body に残り canonicalJson が落とす（既存ハッシュ不変）
    scope: input.scope,
    findings_merkle_root: merkleRoot(findings),
    finding_count: findings.length,
    finding_count_by_severity: countBySeverity(findings),
  };
  const record_hash = canonicalHash(body); // record_hash 自身は含めない
  return { ...body, record_hash };
}

/** 単一レコードの record_hash を再計算して整合を確認。 */
export function recomputeRecordHash(record: EvidenceRecord): string {
  const { record_hash: _omit, ...body } = record;
  void _omit;
  return canonicalHash(body);
}
