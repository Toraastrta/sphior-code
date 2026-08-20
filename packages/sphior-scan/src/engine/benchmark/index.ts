/**
 * benchmark/index.ts — 測定パイプライン公開 API。
 * run-benchmark（node:fs）は server/CLI 専用のため、ここでは純モジュールのみ再輸出する。
 */
export * from "./categories";
export * from "./expected-results";
export * from "./score";
export * from "./report";
// 分野別採点器（いずれも純関数・node:fs なし）: DAST/SCA/IaC + 同一性採点の共通土台。
export * from "./dast-benchmark";
export * from "./identity-score";
export * from "./sca-benchmark";
export * from "./iac-benchmark";
export * from "./grouped-report";
// 実走ドライバ（run-*.ts）は node:fs のため server/CLI 専用。ここでは再輸出しない。
