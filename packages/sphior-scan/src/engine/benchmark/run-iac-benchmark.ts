/**
 * run-iac-benchmark.ts — IaC 誤設定検出を採点する実走オーケストレータ（P0-5 の実行部）
 *
 * ⚠️ server/CLI 専用（node:fs を使う）。クライアントバンドルから import しないこと。
 *
 * 手順:
 *   1. 意図的脆弱構成コーパス dir から expectations.json（IacExpectation[]）を読む。
 *   2. reports/ 配下の Trivy misconfig JSON（`trivy config --format json` の出力）を読み、
 *      本番採用アダプタ trivyToCanonical で CanonicalFinding へ写像 → iac_misconfig を抽出。
 *   3. ルール×リソースで正解と突き合わせて採点（iac-benchmark.ts / identity-score）。
 *
 * エンジン実行境界: Trivy バイナリの起動は外部（コーパスに対し `trivy config` を回して reports/ に
 * JSON を吐く）。本ドライバは「出力の写像 → 採点」を所有し、決定論・オフラインでテストできる。
 * コーパスはリポジトリに含めない。IAC_BENCH_DIR で外部を指す。
 */

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { trivyToCanonical, type TrivyReport } from "@/lib/security-engines/trivy/adapter";
import { scoreIac, type IacExpectation, type IacFindingForScore } from "./iac-benchmark";
import type { GroupedScore } from "./identity-score";

/** AVD/KSV ルール ID からプロバイダを導く（expectations 生成の群分け用）。 */
export function providerForRuleId(ruleId: string): string {
  const id = ruleId.trim().toUpperCase();
  // Trivy は版によって `AVD-AWS-0086`（旧）と `AWS-0086`（0.72 系・m.ID）の両形を出す。
  // アダプタは m.ID を優先するため、裸の <PROVIDER>-NNNN 形も同義として扱う。
  if (id.startsWith("AVD-AWS") || id.startsWith("AWS-")) return "aws";
  if (id.startsWith("AVD-AZU") || id.startsWith("AZU-")) return "azure";
  if (id.startsWith("AVD-GCP") || id.startsWith("GCP-")) return "gcp";
  if (id.startsWith("KSV") || id.startsWith("AVD-KUBE") || id.startsWith("AVD-KCV")) return "kubernetes";
  if (id.startsWith("DS-") || id.startsWith("AVD-DS")) return "docker";
  return "unknown";
}

/**
 * Trivy レポート → IacExpectation[]（較正用）。
 * 意図的脆弱コーパスに `trivy config` を回した出力から、報告された全誤設定を isReal で正解化する。
 * resource:line は Trivy 自身の出力由来なので**版差で行がずれても一致**する（行を推測しない）。
 * 純粋な脆弱コーパスは isReal=true、準拠コーパスの検証には isReal=false を渡す。
 */
export function iacExpectationsFromReport(report: TrivyReport, isReal = true): IacExpectation[] {
  return trivyReportToIacFindings(report).map((f) => ({
    provider: providerForRuleId(f.ruleId),
    resource: f.resource,
    ruleId: f.ruleId,
    isReal,
  }));
}

export interface RunIacBenchmarkOptions {
  /** コーパスのルート（expectations.json と reports/*.json を含む）。 */
  dir: string;
}

export interface RunIacBenchmarkResult {
  score: GroupedScore;
  /** 採点に用いた正解ケース数。 */
  cases: number;
  /** 読み込んだ Trivy レポート数。 */
  reportsRead: number;
}

/**
 * Trivy レポート → IacFindingForScore[]（純関数・テスト可能）。
 * resource は "<target>:<startLine>" 規約で採り、expectations もこの形で照合する。
 */
export function trivyReportToIacFindings(report: TrivyReport): IacFindingForScore[] {
  return trivyToCanonical(report)
    .filter((f) => f.kind === "iac_misconfig")
    .map((f) => ({
      resource: `${f.location.path}:${f.location.start_line}`,
      ruleId: f.rule_id,
    }));
}

/** コーパスを走査して採点する。 */
export function runIacBenchmark(opts: RunIacBenchmarkOptions): RunIacBenchmarkResult {
  const expPath = join(opts.dir, "expectations.json");
  if (!existsSync(expPath)) throw new Error(`expectations.json not found under ${opts.dir}`);
  const expectations = JSON.parse(readFileSync(expPath, "utf8")) as IacExpectation[];

  const reportsDir = join(opts.dir, "reports");
  const files = existsSync(reportsDir) ? readdirSync(reportsDir).filter((f) => f.endsWith(".json")).sort() : [];

  const findings: IacFindingForScore[] = [];
  for (const f of files) {
    const report = JSON.parse(readFileSync(join(reportsDir, f), "utf8")) as TrivyReport;
    findings.push(...trivyReportToIacFindings(report));
  }

  return { score: scoreIac(expectations, findings), cases: expectations.length, reportsRead: files.length };
}
