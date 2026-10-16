#!/usr/bin/env node
/**
 * sphior-code-mcp — Stdio entrypoint for MCP clients.
 *
 * 起動方法:
 *   SPHIOR_API_KEY=sk_live_xxx npx -y @sphior/code-mcp
 *
 * 環境変数:
 *   SPHIOR_API_KEY  (required)  Bearer API key from sphior.com/app?settings=api
 *   SPHIOR_API_BASE (optional)  Override base URL. Default: https://sphior.com/api/v1
 *   SPHIOR_TIMEOUT  (optional)  Request timeout in ms. Default: 30000
 *   SPHIOR_DEBUG    (optional)  Enable debug logging to stderr. Default: false
 */

import { startServer } from "../dist/index.js";

startServer().catch((err) => {
  // stderr only — stdout is reserved for the MCP protocol
  process.stderr.write(`[sphior-code-mcp] Fatal: ${err?.message ?? String(err)}\n`);
  process.exit(1);
});
