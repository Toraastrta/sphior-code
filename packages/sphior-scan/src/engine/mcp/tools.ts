/**
 * tools.ts — SPHIOR CODE の MCP ツール定義とハンドラ（設計 §0.6 / §4.4）
 *
 * 「裏で決定論検知 → MCP で顧客 AI に渡して直させる」を実現する層。
 * `sphior-mcp` サーバがこの定義を登録し、宿主エージェント（Claude Code /
 * Cursor / Copilot / JetBrains AI）が呼ぶ。自前 LLM は一切使わない。
 *
 * - engine-backed（scan_files / explain_finding）: 純関数。DB 不要。
 * - data-backed（list_findings / get_finding / get_evidence_pack）:
 *   `MCPFindingProvider` を注入（scan パッケージは DB 非依存を維持）。
 */

import type { CanonicalFinding } from "../types";
import { runScan, type ScanFile } from "../run";
import type { ScaInput } from "../sca/adapt";
import { buildFixContext, buildFixContexts, type FixContext } from "./fix-context";

/** MCP に公開するツールのメタ（登録用。JSON Schema は最小限）。 */
export interface McpToolSpec {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

/** DB 由来 finding/証跡を供給する依存（sphior-mcp 側で実装）。 */
export interface MCPFindingProvider {
  listFindings(input: { repo: string; ref?: string }): Promise<CanonicalFinding[]>;
  getFinding(input: { finding_id: string }): Promise<CanonicalFinding | null>;
  /** 独立検証可能な evidence pack（署名マニフェスト付き）を返す。 */
  getEvidencePack(input: { repo: string; ref?: string }): Promise<unknown>;
}

// ── engine-backed ハンドラ（純関数・コードはローカルで処理） ──

/** 渡されたファイル群を決定論スキャンして findings を返す（scan_files/scan_diff）。 */
export function handleScanFiles(input: { files: ScanFile[]; sca?: ScaInput[] }): {
  findings: CanonicalFinding[];
  engine_version: string;
  ruleset_version: string;
} {
  const { findings, engine_version, ruleset_version } = runScan({
    files: input.files ?? [],
    sca: input.sca ?? [],
  });
  return { findings, engine_version, ruleset_version };
}

/** finding → 顧客 AI 向け決定論 FixContext（コード非送信）。 */
export function handleExplainFinding(input: { finding: CanonicalFinding }): FixContext {
  return buildFixContext(input.finding);
}

/** findings → FixContext[]（severity 順・修正キュー用）。 */
export function handleExplainFindings(input: { findings: CanonicalFinding[] }): FixContext[] {
  return buildFixContexts(input.findings ?? []);
}

// ── data-backed ハンドラ（provider 経由） ──

export async function handleListFindings(
  provider: MCPFindingProvider,
  input: { repo: string; ref?: string },
): Promise<CanonicalFinding[]> {
  return provider.listFindings(input);
}

export async function handleGetFinding(
  provider: MCPFindingProvider,
  input: { finding_id: string },
): Promise<{ finding: CanonicalFinding; fix: FixContext } | null> {
  const finding = await provider.getFinding(input);
  if (!finding) return null;
  return { finding, fix: buildFixContext(finding) };
}

export async function handleGetEvidencePack(
  provider: MCPFindingProvider,
  input: { repo: string; ref?: string },
): Promise<unknown> {
  return provider.getEvidencePack(input);
}

/**
 * 公開ツールのカタログ（sphior-mcp が登録）。説明はエージェントが用途を
 * 正しく選べるよう決定論・簡潔に。source を送らない旨を明記。
 */
export const MCP_TOOL_SPECS: McpToolSpec[] = [
  {
    name: "sphior_scan_files",
    description:
      "Deterministically scan provided files for hard-coded secrets, insecure code patterns (CWE), " +
      "and vulnerable dependencies. Returns canonical findings. No AI, fully reproducible.",
    input_schema: {
      type: "object",
      properties: {
        files: {
          type: "array",
          items: {
            type: "object",
            properties: { path: { type: "string" }, text: { type: "string" } },
            required: ["path", "text"],
          },
        },
        sca: { type: "array", items: { type: "object" } },
      },
      required: ["files"],
    },
  },
  {
    name: "sphior_explain_finding",
    description:
      "Turn a SPHIOR finding into deterministic remediation guidance (why it matters, fix steps, " +
      "references). Source code is NOT included — open the file in your workspace to fix it.",
    input_schema: {
      type: "object",
      properties: { finding: { type: "object" } },
      required: ["finding"],
    },
  },
  {
    name: "sphior_list_findings",
    description:
      "List the latest deterministic findings recorded for a repository/ref from SPHIOR's " +
      "tamper-evident evidence records.",
    input_schema: {
      type: "object",
      properties: { repo: { type: "string" }, ref: { type: "string" } },
      required: ["repo"],
    },
  },
  {
    name: "sphior_get_finding",
    description:
      "Fetch one finding by id plus its deterministic fix context (no source code included).",
    input_schema: {
      type: "object",
      properties: { finding_id: { type: "string" } },
      required: ["finding_id"],
    },
  },
  {
    name: "sphior_get_evidence_pack",
    description:
      "Return the independently-verifiable evidence pack (Merkle root, hash-chain, signature " +
      "manifest) for a repository/ref — for auditors.",
    input_schema: {
      type: "object",
      properties: { repo: { type: "string" }, ref: { type: "string" } },
      required: ["repo"],
    },
  },
];
