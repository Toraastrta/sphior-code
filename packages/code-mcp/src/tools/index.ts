/**
 * tools/index.ts — MCP tool 定義一覧
 *
 * 各 tool は:
 *   - definition: MCP プロトコル仕様で公開するメタ情報
 *   - handler:    実際の処理 (api クライアントを呼び出して structured 結果を返す)
 *
 * Zod schema で実行時バリデーションし、不正パラメータは早期エラー化する。
 */

import { z } from "zod";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { api, SphiorApiError } from "../api-client.js";
import { log } from "../logger.js";
import { CONFIG } from "../config.js";
import { localFixContext } from "../local-scan.js";

// ── Tool result wrapper ───────────────────────────────────────────────────────

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

function ok(payload: unknown): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
  };
}

function err(message: string): ToolResult {
  return {
    content: [{ type: "text", text: message }],
    isError: true,
  };
}

/**
 * cloud 専用ツールのガード。local モードでは鍵が無いので API を叩けない。
 * 黙って失敗させず、「何が要るか」を返して行き止まりにしない。
 */
function requiresCloud(tool: string): ToolResult | null {
  if (CONFIG.mode === "cloud") return null;
  return err(
    `${tool} requires a SPHIOR account (SPHIOR_API_KEY).\n` +
    `You are running in local mode. Without a key you can use get_fix_context and health_check.\n` +
    `get_fix_context scans the local workspace and returns findings ready to fix.`,
  );
}

async function safe<T>(fn: () => Promise<T>): Promise<ToolResult> {
  try {
    const result = await fn();
    return ok(result);
  } catch (e) {
    if (e instanceof SphiorApiError) {
      return err(e.toUserMessage());
    }
    const msg = e instanceof Error ? e.message : String(e);
    log.error("Unexpected tool error", { error: msg });
    return err(`Internal error: ${msg}`);
  }
}

// ── Schemas ───────────────────────────────────────────────────────────────────

const SeverityEnum = z.enum(["critical", "high", "medium", "low"]);
const StatusEnum   = z.enum(["open", "resolved", "all"]);

const ListFindingsArgs = z.object({
  severity: SeverityEnum.optional().describe("Filter by severity"),
  status:   StatusEnum.optional().describe("Filter by triage status. Default: open"),
  limit:    z.number().int().min(1).max(100).optional().describe("Max number of results (1-100). Default: 20"),
});

const FindingIdArgs = z.object({
  findingId: z.string().min(1).describe("Finding UUID — obtain via list_findings"),
});

const ResolveArgs = FindingIdArgs.extend({
  reason: z.string().max(500).optional().describe("Optional human-readable reason for closing"),
});

const FpArgs = FindingIdArgs.extend({
  reason: z.string().max(500).optional().describe("Optional reason why this is a false positive"),
});

const VerifyEvidenceArgs = z.object({
  repo:        z.string().optional().describe("Repository full_name (owner/repo). Omit for all."),
  includePack: z.boolean().optional().describe("Include the independently-verifiable evidence pack (records + SHA-256 manifest)."),
});

const FixContextArgs = z.object({
  path:      z.string().optional().describe("Local directory to scan (local mode only). Defaults to the current workspace."),
  repo:      z.string().optional().describe("Repository full_name (owner/repo). Omit for the latest scanned repo."),
  findingId: z.string().optional().describe("A specific finding fingerprint to fix. Omit for all findings."),
  severity:  SeverityEnum.optional().describe("Filter to one severity."),
});

// ── Tool definitions (MCP 仕様) ───────────────────────────────────────────────

export const TOOLS: Tool[] = [
  {
    name: "list_findings",
    description:
      "List security vulnerabilities (SAST + SCA) detected by SPHIOR CODE across the user's GitHub repositories. " +
      "Use this when the user asks about security issues, vulnerabilities, or CVEs in their code. " +
      "Returns up to 100 findings ordered by detection date (newest first).",
    inputSchema: {
      type: "object",
      properties: {
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level",
        },
        status: {
          type: "string",
          enum: ["open", "resolved", "all"],
          description: "Filter by triage status. Default: open",
        },
        limit: {
          type: "number",
          minimum: 1,
          maximum: 100,
          description: "Max number of results (1-100). Default: 20",
        },
      },
    },
  },
  {
    name: "get_finding",
    description:
      "Fetch full details of a single security finding by ID — includes CVSS score, CWE classification, " +
      "exact file path and line number, vulnerability message, and fix hint. " +
      "Use when the user wants to investigate a specific issue from list_findings.",
    inputSchema: {
      type: "object",
      properties: {
        findingId: { type: "string", description: "Finding UUID — obtain via list_findings" },
      },
      required: ["findingId"],
    },
  },
  {
    name: "get_security_summary",
    description:
      "Get the user's overall security posture: counts by severity, last scan time, and number of monitored repos. " +
      "Use this when the user wants a high-level overview of their security health.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "resolve_finding",
    description:
      "Mark a finding as resolved (e.g., after applying a fix). " +
      "Use only when the vulnerability has actually been remediated. " +
      "For false positives, use mark_false_positive instead.",
    inputSchema: {
      type: "object",
      properties: {
        findingId: { type: "string", description: "Finding UUID" },
        reason:    { type: "string", maxLength: 500, description: "Optional reason for closing" },
      },
      required: ["findingId"],
    },
  },
  {
    name: "mark_false_positive",
    description:
      "Mark a finding as a false positive (the reported vulnerability is not actually exploitable). " +
      "Use this when the AI's detection is incorrect for a specific code context.",
    inputSchema: {
      type: "object",
      properties: {
        findingId: { type: "string", description: "Finding UUID" },
        reason:    { type: "string", maxLength: 500, description: "Optional reason why this is a false positive" },
      },
      required: ["findingId"],
    },
  },
  {
    name: "health_check",
    description:
      "Verify connectivity and authentication with the SPHIOR CODE API. " +
      "Returns service version and current security summary. " +
      "Use this to debug connection issues.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "get_fix_context",
    description:
      "Scan for security problems and get deterministic remediation guidance so YOU (the AI agent) can fix them. " +
      "Works with no account: without SPHIOR_API_KEY it scans the local workspace with the bundled engine. " +
      "SPHIOR does not generate code or transmit source — open the referenced file in your workspace, read the " +
      "code yourself, and apply the fix. Returns why-it-matters, remediation steps, exact location, and references. " +
      "Findings at the same line are merged into one entry; `also` lists the others and one fix must satisfy all. " +
      "A human must review before merge.",
    inputSchema: {
      type: "object",
      properties: {
        path:       { type: "string", description: "Local mode only: directory to scan. Omit to scan the directory this server was launched in. Use it to narrow a large repository." },
        repo:       { type: "string", description: "Cloud mode only: repository full_name (owner/repo). Omit for the latest scanned repo." },
        findingId:  { type: "string", description: "A specific finding fingerprint to fix. Omit for all findings." },
        severity:   { type: "string", enum: ["critical", "high", "medium", "low"], description: "Filter to one severity." },
      },
    },
  },
  {
    name: "verify_evidence",
    description:
      "Independently verify SPHIOR's tamper-evident code evidence chain (Merkle root + hash-chain + commit anchor). " +
      "Confirms the deterministic scan records were not altered — for auditors. No source code is returned.",
    inputSchema: {
      type: "object",
      properties: {
        repo:        { type: "string", description: "Filter to one repository (full_name). Omit for all." },
        includePack: { type: "boolean", description: "Include the independently-verifiable evidence pack (records + SHA-256 manifest)." },
      },
    },
  },
];

// ── Handlers (name → callable) ────────────────────────────────────────────────

type Handler = (args: unknown) => Promise<ToolResult>;

export const HANDLERS: Record<string, Handler> = {
  list_findings: async (args) => {
    const gate = requiresCloud("list_findings"); if (gate) return gate;
    const a = ListFindingsArgs.parse(args ?? {});
    return safe(() => api.listFindings(a));
  },

  get_finding: async (args) => {
    const gate = requiresCloud("get_finding"); if (gate) return gate;
    const a = FindingIdArgs.parse(args);
    return safe(() => api.getFinding(a.findingId));
  },

  get_security_summary: async () => {
    const gate = requiresCloud("get_security_summary"); if (gate) return gate;
    return safe(() => api.getSummary());
  },


  resolve_finding: async (args) => {
    const gate = requiresCloud("resolve_finding"); if (gate) return gate;
    const a = ResolveArgs.parse(args);
    return safe(() => api.resolveFinding(a.findingId, a.reason));
  },

  mark_false_positive: async (args) => {
    const gate = requiresCloud("mark_false_positive"); if (gate) return gate;
    const a = FpArgs.parse(args);
    return safe(() => api.markFalsePositive(a.findingId, a.reason));
  },

  health_check: async () => {
    return safe(async () => {
      const { summary } = await api.getSummary();
      return {
        status: "ok",
        api_reachable: true,
        repos_monitored: summary.repos_monitored,
        open_findings:   summary.total_open,
        version:         "1.0.0",
      };
    });
  },

  get_fix_context: async (args) => {
    const a = FixContextArgs.parse(args ?? {});
    // local モード: サーバーを使わず同梱エンジンでワークスペースを走査する
    if (CONFIG.mode === "local") {
      return safe(() => localFixContext({
        path: a.path, findingId: a.findingId, severity: a.severity, timeoutMs: CONFIG.timeoutMs,
      }));
    }
    return safe(() => api.getFixContext({ repo: a.repo, findingId: a.findingId, severity: a.severity }));
  },

  verify_evidence: async (args) => {
    const gate = requiresCloud("verify_evidence"); if (gate) return gate;
    const a = VerifyEvidenceArgs.parse(args ?? {});
    return safe(() => api.verifyEvidence({ repo: a.repo, includePack: a.includePack }));
  },
};
