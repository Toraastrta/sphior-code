#!/usr/bin/env node
/**
 * sphior-ai-governance-mcp — Stdio entrypoint for MCP clients.
 *
 * 起動方法:
 *   SPHIOR_AIGOV_TOKEN=<token> npx -y sphior-ai-governance-mcp
 *
 * 環境変数:
 *   SPHIOR_AIGOV_TOKEN    (required)  取込トークン (https://sphior.com/app?settings=aigov)
 *   SPHIOR_AIGOV_ENDPOINT (optional)  取込エンドポイントの上書き。既定 https://sphior.com/api/ai-governance/ingest
 *   SPHIOR_TIMEOUT        (optional)  リクエストタイムアウト(ms)。既定 30000
 *   SPHIOR_DEBUG          (optional)  stderr デバッグログ。既定 false
 */

import { startServer } from "../dist/index.js";

startServer().catch((err) => {
  // stderr のみ — stdout は MCP プロトコル専用
  process.stderr.write(`[sphior-ai-governance-mcp] Fatal: ${err?.message ?? String(err)}\n`);
  process.exit(1);
});
