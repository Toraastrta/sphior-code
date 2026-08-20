/**
 * sphior-scan エンジン — 公開 API（設計 §4.1）
 *
 * framework 非依存の決定論スキャンコア。CI(GitHub Action) / IDE(LSP) / MCP /
 * CLI から共有される。将来 `packages/sphior-scan` として抽出予定。
 */

export * from "./types";
export { canonicalJson, canonicalHash, sha256 } from "./canonical";
export { detectSecrets, detectSecretsInFiles, maskSecret, type DetectOptions } from "./secrets/detect";
export { shannonEntropy, looksHighEntropy } from "./secrets/entropy";
export { SECRET_RULES } from "./secrets/rules";
export { toSarif, type SarifMeta } from "./sarif";
export { detectPatterns, detectPatternsInFiles, type PatternOptions } from "./patterns/detect";
export { PATTERN_RULES } from "./patterns/rules";
export { scaToCanonical, type ScaInput } from "./sca/adapt";
export { runScan, type RunScanInput, type RunScanResult, type ScanFile } from "./run";
export { ENGINE_VERSION, RULESET_VERSION } from "./version";
// Evidence Spine（moat）
export { merkleRoot, countBySeverity } from "./evidence/merkle";
export { buildEvidenceRecord, recomputeRecordHash, type EvidenceRecord, type EvidenceRecordInput } from "./evidence/record";
export { verifyChain, type ChainVerifyResult } from "./evidence/chain";
export { buildPackManifest, verifyPackManifest, type PackManifest, type PackEntry, type PackVerifyResult } from "./evidence/pack";
export { rowToEvidenceRecord, verifyEvidenceRows, verifyEvidenceWindow, buildEvidencePackFromRows, type EvidenceRow, type RowsVerifyResult, type EvidencePack } from "./evidence/verify-rows";
// CLI / 収集（GitHub Action・self-host の基盤）
export { collectSourceFiles, type CollectedFile, type CollectOptions } from "./collect";
export { runCli, type CliResult, type CliContext } from "./cli";
// Framework マッピング（North Star）
export { mapFindingToControls, summarizeControls, type ControlRef, type ControlCoverage, type Framework } from "./framework/map";
// MCP ハンドオフ（§0.6 自前 AI ゼロ・修正は顧客 AI へ）
export { buildFixContext, buildFixContexts, LOCATION_STEP_PREFIX, type FixContext } from "./mcp/fix-context";
export {
  handleScanFiles, handleExplainFinding, handleExplainFindings,
  handleListFindings, handleGetFinding, handleGetEvidencePack,
  MCP_TOOL_SPECS, type McpToolSpec, type MCPFindingProvider,
} from "./mcp/tools";
