/**
 * server.ts — MCP Server セットアップ (stdio transport)
 *
 * tools/resources を登録し、JSON-RPC リクエストを処理する。
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { CONFIG } from "./config.js";
import { log } from "./logger.js";
import { TOOLS, HANDLERS } from "./tools/index.js";
import { api } from "./api-client.js";

export async function startServer(): Promise<void> {
  log.info(`SPHIOR Code MCP server starting`, { version: CONFIG.version, baseUrl: CONFIG.baseUrl });

  const server = new Server(
    {
      name:    "sphior-code",
      version: CONFIG.version,
    },
    {
      capabilities: {
        tools:     {},
        resources: {},
      },
    },
  );

  // ── tools/list ──────────────────────────────────────────────────────────
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  // ── tools/call ──────────────────────────────────────────────────────────
  // SDK 1.29+ では handler 戻り値の型が ServerResult union に拡張されているため
  // ローカル ToolResult 形式 ({content, isError}) を CallToolResult として返す。
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    log.debug(`tools/call ${name}`, { args });

    const handler = HANDLERS[name];
    if (!handler) {
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      } as never;
    }

    try {
      const result = await handler(args);
      return result as never;
    } catch (e) {
      // Zod 検証エラーなど handler 内で投げられた未捕捉例外
      if (e instanceof z.ZodError) {
        const msg = `Invalid arguments for ${name}: ${e.issues.map((i) => `${i.path.join(".")} - ${i.message}`).join("; ")}`;
        return { content: [{ type: "text", text: msg }], isError: true } as never;
      }
      const msg = e instanceof Error ? e.message : String(e);
      log.error("Unhandled tool error", { tool: name, error: msg });
      return { content: [{ type: "text", text: `Internal error: ${msg}` }], isError: true } as never;
    }
  });

  // ── resources/list — 動的 URI で findings を露出 ─────────────────────────
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    try {
      const { findings } = await api.listFindings({ status: "open", limit: 50 });
      return {
        resources: [
          {
            uri:         "sphior-code://summary",
            name:        "Security Summary",
            description: "Aggregate security posture (counts by severity, last scan time)",
            mimeType:    "application/json",
          },
          ...findings.map((f) => ({
            uri:         `sphior-code://findings/${f.id}`,
            name:        `${f.severity.toUpperCase()} — ${f.title}`,
            description: `${f.file_path}:${f.line_start} · ${f.repo_full_name ?? "unknown repo"}`,
            mimeType:    "application/json",
          })),
        ],
      };
    } catch (e) {
      log.warn("resources/list failed", { error: e instanceof Error ? e.message : String(e) });
      return { resources: [] };
    }
  });

  // ── resources/read ──────────────────────────────────────────────────────
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;

    if (uri === "sphior-code://summary") {
      const { summary } = await api.getSummary();
      return {
        contents: [
          { uri, mimeType: "application/json", text: JSON.stringify(summary, null, 2) },
        ],
      };
    }

    const match = uri.match(/^sphior-code:\/\/findings\/(.+)$/);
    if (match) {
      const findingId = match[1];
      const { finding } = await api.getFinding(findingId);
      return {
        contents: [
          { uri, mimeType: "application/json", text: JSON.stringify(finding, null, 2) },
        ],
      };
    }

    throw new Error(`Unsupported resource URI: ${uri}`);
  });

  // ── Transport 接続 ──────────────────────────────────────────────────────
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log.info(`Ready to receive MCP requests on stdio`);

  // SIGTERM / SIGINT で graceful shutdown
  const shutdown = (signal: string) => {
    log.info(`Shutting down on ${signal}`);
    process.exit(0);
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT",  () => shutdown("SIGINT"));
}
