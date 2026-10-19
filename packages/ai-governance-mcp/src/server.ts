/**
 * server.ts — MCP Server セットアップ (stdio transport)。tools のみ公開。
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { CONFIG } from "./config.js";
import { log } from "./logger.js";
import { TOOLS, HANDLERS } from "./tools/index.js";

export async function startServer(): Promise<void> {
  log.info("SPHIOR AI Governance MCP server starting", { version: CONFIG.version, endpoint: CONFIG.endpoint });

  const server = new Server(
    { name: "sphior-ai-governance", version: CONFIG.version },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    log.debug(`tools/call ${name}`);
    const handler = HANDLERS[name];
    if (!handler) {
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true } as never;
    }
    try {
      return (await handler(args)) as never;
    } catch (e) {
      if (e instanceof z.ZodError) {
        const msg = `Invalid arguments for ${name}: ${e.issues.map((i) => `${i.path.join(".")} - ${i.message}`).join("; ")}`;
        return { content: [{ type: "text", text: msg }], isError: true } as never;
      }
      const msg = e instanceof Error ? e.message : String(e);
      log.error("Unhandled tool error", { tool: name, error: msg });
      return { content: [{ type: "text", text: `Internal error: ${msg}` }], isError: true } as never;
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  log.info("Ready to receive MCP requests on stdio");

  const shutdown = (signal: string) => { log.info(`Shutting down on ${signal}`); process.exit(0); };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
