/**
 * types.ts — sphior-scan エンジンの Canonical Finding スキーマ（設計 §5 正本）
 *
 * このモジュール群は framework 非依存の純 TS（Next/React に依存しない）。
 * 将来 `packages/sphior-scan` の CLI/LSP として抽出できるよう、副作用と
 * 外部依存を持たない。決定論・再現性が監査証跡の前提（設計 §2）。
 */

export const SCHEMA_VERSION = 1 as const;

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "likely" | "needs_review";
export type FindingKind = "sast_secret" | "sast_pattern" | "sca" | "iac_misconfig";

/**
 * 検出元エンジンの識別子（マルチエンジン統合・PLAN §4.1）。内部識別であり顧客面には出さない。
 * 採用 OSS は当面 permissive のみ（PLAN D11）。
 */
export type FindingEngine =
  | "sphior_sast"   // 自前 SAST（secrets/pattern/taint）
  | "sphior_sca"    // 自前/OSV 経路の SCA
  | "trivy"         // SCA/IaC/コンテナ/secrets（Apache-2.0）
  | "zap"           // DAST（Apache-2.0）
  | "nuclei";       // DAST/インフラ（MIT）

/**
 * 能動検証（Proof-Based）の結果（PLAN §4.4）。悪用可能性を安全に確認した事実。
 * over-claim しないため 3 値のみ（合否・達成は言わない）。
 */
export type ProofVerdict = "confirmed" | "inconclusive" | "refuted";

export interface FindingProof {
  verdict: ProofVerdict;
  /** 検証手法の内部識別（例 "time_based_sqli" / "reflected_xss"）。顧客面には出さない。 */
  method?: string;
  /** 検証結果を封緘した Evidence レコードの参照（source_ref）。改竄不能な証拠へのポインタ。 */
  evidence_ref?: string;
}

/**
 * 抑制の記録（suppress.ts）。「見なかった」ではなく「見たうえで受け入れた」を残す。
 * finding を消さずにこれを付け、`RunScanResult.suppressed` 側へ分ける。
 */
export interface FindingSuppression {
  /** `.sphiorignore` 由来か、ソース中のインラインコメント由来か。 */
  by: "config" | "inline";
  /** ルールを限定した抑制か（false = その行/ファイルの全ルール）。 */
  rule_scoped: boolean;
  /** 書かれていれば受け入れ理由。監査で最初に読まれる 1 行。 */
  justification?: string;
  /** 由来の位置（例 ".sphiorignore:12" / "src/a.ts:41"）。人に戻せるようにする。 */
  source: string;
}

export interface FindingLocation {
  path: string; // repo 相対・POSIX 区切り
  start_line: number; // 1-based
  start_col: number; // 1-based
  end_line: number;
  end_col: number;
}

/**
 * Canonical Finding — 全 surface（CI/IDE/MCP）が生成する正規化 finding。
 * 決定論シリアライズでバイト一致 → 同一ハッシュ（証跡の再現性の要）。
 */
export interface CanonicalFinding {
  schema_version: typeof SCHEMA_VERSION;
  kind: FindingKind;
  rule_id: string;
  cwe?: string; // e.g. "CWE-798"
  owasp?: string; // e.g. "A07:2021"
  severity: Severity;
  confidence: Confidence;
  title: string;
  message: string;
  location: FindingLocation;
  /** マッチした実体（秘密値等）の SHA-256。生値は決して保存しない。 */
  snippet_hash: string;
  /** 秘密のマスク済みプレビュー（例: "AKI…7E"）。表示・ログ用。 */
  masked?: string;
  provider?: string; // secret のプロバイダ / sca のパッケージ等
  remediation?: string;
  references?: string[];
  /**
   * 行ズレに強い論理識別子。delta 追跡（new/resolved/carried）の鍵。
   * = sha256(canonical({ rule_id, path, locator })) — locator は種別により
   * 秘密のハッシュや package coord 等の行非依存な値。
   */
  fingerprint: string;
  /**
   * ── 以下は optional・後方互換（PLAN Phase 0 / P0-1）──
   * undefined 既定のため canonicalJson で除去され、既存 finding のハッシュ/fingerprint は不変。
   */
  /** 検出元エンジン（マルチエンジン統合で付与）。 */
  engine?: FindingEngine;
  /** 同一 fingerprint を複数エンジンが検出した場合の全エンジン集合（確度昇格の根拠）。 */
  engines?: FindingEngine[];
  /** Proof-Based 検証の結果（付与された場合のみ）。 */
  proof?: FindingProof;
  /**
   * 抑制の記録（抑制された finding にのみ付く）。
   * active な finding には付かないため、既存 finding のハッシュ/fingerprint は不変。
   */
  suppression?: FindingSuppression;
  /** この finding を封緘した Evidence レコードの参照（source_ref）。 */
  evidence_ref?: string;
}

/** エンジン実行の来歴（証跡 record に刻む・再現性の担保）。 */
export interface ScanProvenance {
  engine_version: string;
  ruleset_version: string;
  advisory_db_snapshot?: string; // SCA 用（OSV/GHSA スナップショット id）
}
