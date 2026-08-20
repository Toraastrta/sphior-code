/**
 * fix-context.ts — MCP ハンドオフ payload（設計 §0.6 / §4.4）
 *
 * SPHIOR は自前 LLM を持たない。決定論エンジンが見つけた finding を、顧客が
 * 既に持つ AI エージェント（JetBrains AI / Copilot / Cursor / Claude Code）へ
 * MCP 経由で渡し、その AI に修正させる。
 *
 * ここで組み立てる FixContext は「顧客 AI に渡す唯一の payload」。
 * 原則:
 *  - **ソースコード本体は含めない**。エージェントは自分のワークスペースで
 *    location を開いて実コードを読む（データ境界の最小化）。
 *  - 生の秘密値は含めない（masked プレビューのみ）。
 *  - 説明・修正手順は決定論的に生成（AI 生成でない＝再現可能・責任明確）。
 */

import type { CanonicalFinding, Confidence, FindingKind, Severity } from "../types";

/** 顧客 AI に手渡す修正コンテキスト（決定論・コード非送信）。 */
export interface FixContext {
  /** 行ズレに強い論理 ID（= finding.fingerprint）。 */
  finding_id: string;
  rule_id: string;
  kind: FindingKind;
  severity: Severity;
  confidence: Confidence;
  cwe?: string;
  owasp?: string;
  title: string;
  summary: string;
  /** エージェントがワークスペースで開くべき位置（コード本体は渡さない）。 */
  location: { path: string; start_line: number; end_line: number };
  /** secret のマスク済みプレビュー（生値ではない）。 */
  masked_preview?: string;
  provider?: string;
  /** なぜ問題か（決定論的な説明。CWE/種別ベース）。 */
  why: string;
  /** 決定論的な修正手順。 */
  remediation_steps: string[];
  references: string[];
  /** 顧客 AI への行動指示（コードは含めない・人間レビュー前提）。 */
  agent_instructions: string;
  /** データ境界の明示（監査・信頼のため常に付与）。 */
  data_boundary_note: string;
}

const DATA_BOUNDARY_NOTE =
  "SPHIOR does not transmit your source code. This payload contains only finding metadata " +
  "and deterministic remediation guidance. Read the actual code from your local workspace.";

/** CWE → 決定論的な「なぜ問題か」。未知の CWE は種別の汎用説明にフォールバック。 */
const WHY_BY_CWE: Record<string, string> = {
  "CWE-798":
    "A hard-coded credential was found in source. Committed secrets can be extracted from git history and reused to access production systems.",
  "CWE-95":
    "Dynamic code evaluation (eval) executes arbitrary strings as code; attacker-controlled input leads to remote code execution.",
  "CWE-78":
    "OS command injection: untrusted input reaches a shell command and can execute arbitrary commands on the host.",
  "CWE-79":
    "Cross-site scripting: unescaped input rendered as HTML lets an attacker run script in the victim's browser.",
  "CWE-295":
    "TLS certificate validation is disabled, exposing traffic to man-in-the-middle interception.",
  "CWE-327":
    "A weak/broken cryptographic primitive is used; it does not provide the integrity or confidentiality assumed.",
  "CWE-502":
    "Deserialization of untrusted data can instantiate arbitrary objects and lead to remote code execution.",
};

function whyForFinding(f: CanonicalFinding): string {
  if (f.cwe && WHY_BY_CWE[f.cwe]) return WHY_BY_CWE[f.cwe];
  switch (f.kind) {
    case "sast_secret":
      return WHY_BY_CWE["CWE-798"];
    case "sca":
      return (
        "A dependency matches a known security advisory. Vulnerable dependencies inherit the " +
        "advisory's impact into your application until upgraded or mitigated."
      );
    default:
      return f.message;
  }
}

function remediationStepsFor(f: CanonicalFinding): string[] {
  const path = f.location.path;
  switch (f.kind) {
    case "sast_secret":
      return [
        `Remove the credential from ${path} (line ${f.location.start_line}).`,
        `Revoke/rotate the exposed ${f.provider ?? "credential"} immediately in its provider console.`,
        "Load the value from a secret manager or environment variable instead of source.",
        "Purge the secret from git history if it was committed (e.g. git filter-repo / BFG).",
        "Re-scan to confirm no other copies remain.",
      ];
    case "sca":
      return [
        `Upgrade ${f.provider ?? "the dependency"} to a fixed version per the advisory.`,
        "If no fixed version exists, apply the advisory's mitigation or replace the dependency.",
        "Update the lockfile and re-run the scan to confirm the finding is resolved.",
      ];
    default: {
      const steps: string[] = [`${LOCATION_STEP_PREFIX} ${path}:${f.location.start_line}.`];
      if (f.remediation) steps.push(f.remediation);
      else steps.push(`Apply the secure alternative for ${f.cwe ?? f.rule_id}.`);
      steps.push("Add a regression test covering the fixed behavior.");
      return steps;
    }
  }
}

/**
 * 「どこを見るか」を指す手順の接頭辞。
 *
 * MCP / エージェント向けにはファイルパスが必須（相手はファイルを開くところから始める）。
 * 一方エディタの診断では、その行そのものにカーソルがあるため冗長になる。消費側が文脈に
 * 応じて除去できるよう、接頭辞を名前付きで公開する。
 */
export const LOCATION_STEP_PREFIX = "Review the flagged code at";

function agentInstructions(f: CanonicalFinding): string {
  const loc = `${f.location.path} around line ${f.location.start_line}`;
  const base =
    `Open ${loc} in the workspace you already have access to and read the actual code yourself ` +
    `(it is NOT included here for security). Apply the remediation steps below. This finding was ` +
    `produced deterministically by SPHIOR — do not re-classify or dismiss it. A human must review ` +
    `your change before merge.`;
  if (f.kind === "sast_secret") {
    return `${base} Never print, log, or commit the raw secret value; treat it as already compromised.`;
  }
  return base;
}

/** 単一 finding → 顧客 AI 向け FixContext（決定論・コード非送信）。 */
export function buildFixContext(f: CanonicalFinding): FixContext {
  return {
    finding_id: f.fingerprint,
    rule_id: f.rule_id,
    kind: f.kind,
    severity: f.severity,
    confidence: f.confidence,
    cwe: f.cwe,
    owasp: f.owasp,
    title: f.title,
    summary: f.message,
    location: {
      path: f.location.path,
      start_line: f.location.start_line,
      end_line: f.location.end_line,
    },
    masked_preview: f.masked,
    provider: f.provider,
    why: whyForFinding(f),
    remediation_steps: remediationStepsFor(f),
    references: f.references ?? [],
    agent_instructions: agentInstructions(f),
    data_boundary_note: DATA_BOUNDARY_NOTE,
  };
}

/** 複数 finding → FixContext[]（severity 高→低で安定ソート、決定論）。 */
export function buildFixContexts(findings: CanonicalFinding[]): FixContext[] {
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return findings
    .map(buildFixContext)
    .sort((a, b) => order[a.severity] - order[b.severity]);
}
