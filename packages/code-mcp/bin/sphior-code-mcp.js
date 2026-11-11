#!/usr/bin/env node
/**
 * sphior-code-mcp — Stdio entrypoint for MCP clients.
 *
 * 起動方法:
 *   npx -y sphior-code-mcp                              （local モード・キー不要）
 *   SPHIOR_API_KEY=sk_live_xxx npx -y sphior-code-mcp   （cloud モード）
 *
 * 環境変数:
 *   SPHIOR_API_KEY   (optional)  Bearer API key from sphior.com/app?settings=api。無ければ local モード
 *   SPHIOR_WORKSPACE (optional)  local モードの走査先。Default: 起動ディレクトリ
 *   SPHIOR_API_BASE  (optional)  Override base URL. Default: https://sphior.com/api/v1
 *   SPHIOR_TIMEOUT   (optional)  Local scan / request timeout in ms. Default: 30000
 *   SPHIOR_DEBUG    (optional)  Enable debug logging to stderr. Default: false
 */

import { startServer } from "../dist/index.js";

startServer().catch((err) => {
  // stderr only — stdout is reserved for the MCP protocol
  process.stderr.write(`[sphior-code-mcp] Fatal: ${err?.message ?? String(err)}\n`);
  process.exit(1);
});
