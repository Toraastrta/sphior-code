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
