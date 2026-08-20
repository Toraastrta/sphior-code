/**
 * verify-rows.ts — 永続化済み証跡（DB 行）の独立検証 & evidence pack 生成
 *
 * 設計 §4.5 / §7。`code_evidence_records` から読み戻した行を、監査人が
 * オフラインで検証できる形（EvidenceRecord + pack manifest）に再構成する。
 *
 * 重要（round-trip 不変条件）:
 *   record_hash は `new Date().toISOString()`（ms 精度 "Z"）で hash されるが、
 *   DB の TIMESTAMPTZ は読み戻すと `+00:00` 形式になる。`new Date(x).toISOString()`
 *   で正規化すると元の hash 形式へ**厳密復元**できる（ms 精度・UTC 正準形）。
 *   これにより DB を経由しても record_hash / chain を再計算・独立検証できる。
 */

import type { CanonicalFinding, Severity } from "../types";
import type { EvidenceRecord } from "./record";
import { recomputeRecordHash } from "./record";
import { verifyChain, type ChainVerifyResult } from "./chain";
import { merkleRoot } from "./merkle";
import { canonicalJson } from "../canonical";
import { buildPackManifest, type PackManifest } from "./pack";

/** `code_evidence_records` の1行（DB 非依存の形。列名に一致）。 */
export interface EvidenceRow {
  repo_full_name: string;
  branch: string | null;
  commit_sha: string;
  engine_version: string;
  ruleset_version: string;
  advisory_db_snapshot?: string | null;
  scanned_at: string;
  actor: string | null;
  prev_record_hash: string | null;
  findings_merkle_root: string;
  finding_count: number;
  finding_count_by_severity: Record<string, number>;
  record_hash: string;
  findings: CanonicalFinding[];
  created_at?: string;
  mode?: string | null;
  pr_number?: number | null;
}

/** DB の timestamptz を hash 時の正準形（ms 精度 "Z"）へ戻す。 */
function normalizeScannedAt(s: string): string {
  return new Date(s).toISOString();
}

/** created_at 昇順（chain 順）。 */
function byCreatedAsc(a: EvidenceRow, b: EvidenceRow): number {
  const x = a.created_at ?? "";
  const y = b.created_at ?? "";
  return x < y ? -1 : x > y ? 1 : 0;
}

/** DB 行 → EvidenceRecord（hash 対象 body を厳密復元）。 */
export function rowToEvidenceRecord(row: EvidenceRow): EvidenceRecord {
  return {
    repo: row.repo_full_name,
    branch: row.branch ?? "",
    commit_sha: row.commit_sha,
    engine_version: row.engine_version,
    ruleset_version: row.ruleset_version,
    advisory_db_snapshot: row.advisory_db_snapshot ?? undefined,
    scanned_at: normalizeScannedAt(row.scanned_at),
    actor: row.actor ?? "",
    prev_record_hash: row.prev_record_hash,
    findings_merkle_root: row.findings_merkle_root,
    finding_count: row.finding_count,
    finding_count_by_severity: row.finding_count_by_severity as Record<Severity, number>,
    record_hash: row.record_hash,
  };
}

export interface RowsVerifyResult extends ChainVerifyResult {
  recordCount: number;
  /** findings jsonb が merkle root と不一致だった index（改ざん検知）。 */
  findingsTamperAt?: number;
}

/**
 * DB 行群を独立検証する。created_at 昇順（古い→新しい）が chain 順。
 *  1) 各行の findings から merkle root を再計算 → 保存値と一致（findings 改ざん検知）
 *  2) record_hash 再計算 + prev_record_hash 連鎖（verifyChain）
 */
export function verifyEvidenceRows(rows: EvidenceRow[]): RowsVerifyResult {
  const ordered = [...rows].sort(byCreatedAsc);

  // findings の完全性（merkle 再計算）を先に確認
  for (let i = 0; i < ordered.length; i++) {
    if (merkleRoot(ordered[i].findings) !== ordered[i].findings_merkle_root) {
      return { ok: false, recordCount: ordered.length, findingsTamperAt: i, brokenAt: i, reason: "record_hash_mismatch" };
    }
  }

  const records = ordered.map(rowToEvidenceRecord);
  const chain = verifyChain(records);
  return { ...chain, recordCount: records.length };
}

/**
 * ウィンドウ検証 — 部分列（最新 N 件など）を検証する。genesis（prev=null）を
 * 要求せず、区間内の各レコードの完全性（merkle + record_hash 再計算）と、隣接
 * レコード間のリンクのみ確認する。月次レポートが全チェーンを読まずに直近の
 * 改ざん不可性を示すのに使う。
 */
export function verifyEvidenceWindow(rows: EvidenceRow[]): RowsVerifyResult {
  const ordered = [...rows].sort(byCreatedAsc);
  for (let i = 0; i < ordered.length; i++) {
    const row = ordered[i];
    if (merkleRoot(row.findings) !== row.findings_merkle_root) {
      return { ok: false, recordCount: ordered.length, findingsTamperAt: i, brokenAt: i, reason: "record_hash_mismatch" };
    }
    const rec = rowToEvidenceRecord(row);
    if (recomputeRecordHash(rec) !== rec.record_hash) {
      return { ok: false, recordCount: ordered.length, brokenAt: i, reason: "record_hash_mismatch" };
    }
    if (i > 0 && row.prev_record_hash !== ordered[i - 1].record_hash) {
      return { ok: false, recordCount: ordered.length, brokenAt: i, reason: "chain_link_mismatch" };
    }
  }
  return { ok: true, recordCount: ordered.length };
}

export interface EvidencePack {
  records: EvidenceRecord[];
  verification: RowsVerifyResult;
  manifest: PackManifest;
  /** pack に含めるデータファイル（監査人はこれと manifest で独立検証）。 */
  files: Array<{ name: string; content: string }>;
}

/**
 * DB 行群から独立検証可能な evidence pack を生成。
 * records.json / findings.json を決定論シリアライズし、per-file SHA-256 の
 * manifest を付す。監査人はインスタンスにアクセスせず改ざんを検証できる。
 */
export function buildEvidencePackFromRows(rows: EvidenceRow[]): EvidencePack {
  const verification = verifyEvidenceRows(rows);
  const ordered = [...rows].sort(byCreatedAsc);
  const records = ordered.map(rowToEvidenceRecord);
  const findings = ordered.map((r) => ({ commit_sha: r.commit_sha, record_hash: r.record_hash, findings: r.findings }));

  const files = [
    { name: "records.json", content: canonicalJson(records) },
    { name: "findings.json", content: canonicalJson(findings) },
  ];
  const manifest = buildPackManifest(files.map((f) => ({ name: f.name, bytes: f.content })));
  return { records, verification, manifest, files };
}
