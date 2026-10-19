/**
 * tools/index.ts — MCP tool 定義（AI 実行の記録）。
 *
 * record_ai_execution / record_ai_executions を公開。AI エージェント (Claude/Cursor 等) が
 * 自身の実行を SPHIOR に改竄不能記録できる。§0 厳守: 証跡を残すのみ（準拠証明はしない）。
 */

import { CONFIG } from "../config.js";
import { z } from "zod";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { ingest } from "../client.js";
import { log } from "../logger.js";

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}
function ok(payload: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}
function err(message: string): ToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

// ── Schemas (実行時バリデーション) ────────────────────────────────────────────
const EventSchema = z.object({
  actor:           z.string().optional(),
  model:           z.string().optional(),
  provider:        z.string().optional(),
  model_version:   z.string().optional(),
  policy_decision: z.string().optional(),
  tokens:          z.number().optional(),
  cost:            z.number().optional(),
  latency:         z.number().optional(),
  trace_id:        z.string().optional(),
  occurred_at:     z.string().optional(),
}).passthrough();

const eventJsonSchema = {
  type: "object",
  properties: {
    actor:           { type: "string", description: "Agent or service name" },
    model:           { type: "string", description: "Model display name (your label)" },
    provider:        { type: "string" },
    model_version:   { type: "string" },
    policy_decision: { type: "string", description: "Your outcome, e.g. allow | deny | flag" },
    tokens:          { type: "number" },
    cost:            { type: "number" },
    latency:         { type: "number", description: "ms" },
    trace_id:        { type: "string", description: "Correlation id" },
    occurred_at:     { type: "string", description: "RFC3339; defaults to now" },
  },
  additionalProperties: true,
} as const;

// ── Tool definitions ──────────────────────────────────────────────────────────
export const TOOLS: Tool[] = [
  {
    name: "record_ai_execution",
    description:
      "Record one AI / AI-agent execution as tamper-evident, independently verifiable evidence " +
      "(hash-only — only hashes and metadata are stored). Use this to log what an AI did, with what " +
      "model, and your policy outcome, for ISO 42001 / EU AI Act / SOC 2 evidence.",
    inputSchema: eventJsonSchema as unknown as Tool["inputSchema"],
  },
  {
    name: "record_ai_executions",
    description: "Record multiple AI executions in one call (up to 200). Same fields as record_ai_execution.",
    inputSchema: {
      type: "object",
      properties: {
        events: { type: "array", items: eventJsonSchema, maxItems: 200 },
      },
      required: ["events"],
    } as unknown as Tool["inputSchema"],
  },
];

// 鍵が無い状態はエラーではなく「まだ始めていない」状態。行き止まりにせず、
// 次に何をすればいいかを返す。無料枠があるので、ここが入口になる。
function requiresToken(): ToolResult | null {
  if (CONFIG.token) return null;
  return err(
    "This tool records evidence into your SPHIOR account, so it needs an ingestion token.\n" +
    "1. Create a free account at https://sphior.com\n" +
    "2. Open https://sphior.com/app?settings=aigov and create an ingestion token\n" +
    "3. Set it as SPHIOR_AIGOV_TOKEN in this server's env, then restart\n" +
    // 無料枠の件数はここに焼き込まない。ai-governance-pricing.ts の表（1 万）と
    // ingest が実際に止める AIGOV_FREE_INGEST_CAP（10 万）が食い違っており、
    // どちらを正とするか未決。確定するまで数値は料金ページ 1 箇所に置く。
    "There is a free tier that needs no card — see https://sphior.com/pricing",
  );
}

// ── Handlers ────────────────────────────────────────────────────────────────
export const HANDLERS: Record<string, (args: unknown) => Promise<ToolResult>> = {
  record_ai_execution: async (args) => {
    const gate = requiresToken();
    if (gate) return gate;
    const ev = EventSchema.parse(args ?? {}) as Record<string, unknown>;
    if (ev.occurred_at === undefined) ev.occurred_at = new Date().toISOString();
    const r = await ingest({ event: ev });
    log.debug("record_ai_execution", { ok: r.ok });
    return r.ok ? ok(r) : err(r.error ?? "ingest failed");
  },
  record_ai_executions: async (args) => {
    const gate = requiresToken();
    if (gate) return gate;
    const parsed = z.object({ events: z.array(EventSchema).min(1).max(200) }).parse(args ?? {});
    const events = parsed.events.map((e) => ({ occurred_at: new Date().toISOString(), ...e }));
    const r = await ingest({ events });
    log.debug("record_ai_executions", { ok: r.ok, count: events.length });
    return r.ok ? ok(r) : err(r.error ?? "ingest failed");
  },
};
