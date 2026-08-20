/**
 * iac-benchmark.ts — IaC/コンテナ誤設定 検出精度の採点（PLAN Phase 0 / P0-5・純関数）
 *
 * SAST/DAST/SCA と同じ測定規律を IaC(意図的脆弱構成) にも適用する。
 * 「意図的に脆弱な構成（Terraform/K8s/Dockerfile 等）を固定基準」にし、リソース上のルール適合を測る。
 * 正解は (provider, resource, ruleId, isReal) で与え、エンジン(Trivy misconfig/自前)が報告した
 * 「ルール×リソース」と突き合わせる。CIS/AVD の個別ルール単位で TPR/FPR を出せる。
 *
 * 照合キーは ruleId×resource: 同一ルールでも別リソースは別ケースになり、安全なリソースを誤検知すれば
 * FP、脆弱なリソースを取りこぼせば FN として正しく計上される（採点数理は identity-score を再利用）。
 */

import { scoreIdentity, type IdentityCase, type GroupedScore } from "./identity-score";

/** 意図的脆弱構成の 1 チェック地点に対する正解ラベル。 */
export interface IacExpectation {
  /** 対象プロバイダ（例 "aws" | "kubernetes" | "docker"）。集計群に使う。 */
  provider: string;
  /** 対象リソース識別（例 "main.tf:12" | "deploy.yaml:Pod/web"）。 */
  resource: string;
  /** ルール ID（例 AVD-AWS-0086 / CIS-1.2.3）。 */
  ruleId: string;
  /** true = このルール違反が真に存在（検出すべき）/ false = 適合済みで安全（検出したら FP）。 */
  isReal: boolean;
}

/** エンジンが報告した誤設定の最小形（ルール×リソースを持てば採点できる）。 */
export interface IacFindingForScore {
  provider?: string | null;
  resource: string;
  ruleId: string;
}

/** 照合キー: RULEID@resource（ルール ID は大文字・resource は空白正規化）。 */
export function iacKey(ruleId: string, resource: string): string {
  return `${ruleId.trim().toUpperCase()}@${resource.trim()}`;
}

/** 正解(意図的脆弱構成) + エンジン報告 → provider 群別/全体スコア。 */
export function scoreIac(
  expectations: IacExpectation[],
  findings: IacFindingForScore[],
): GroupedScore {
  const reported = new Set(findings.map((f) => iacKey(f.ruleId, f.resource)));
  const cases: IdentityCase[] = expectations.map((e) => ({
    key: iacKey(e.ruleId, e.resource),
    group: (e.provider || "unknown").trim().toLowerCase(),
    isReal: e.isReal,
  }));
  return scoreIdentity(cases, reported);
}
