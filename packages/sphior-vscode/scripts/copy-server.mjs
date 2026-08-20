/**
 * copy-server.mjs — @sphior/scan の LSP サーバを拡張へ同梱
 *
 * VSIX に自己完結の server.cjs を含めるため、隣接パッケージのビルド成果物を
 * server/ へコピーする（@sphior/scan は事前に `npm run build` 済みであること）。
 */

import { cpSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "..", "sphior-scan", "dist", "server.cjs");
const destDir = join(here, "..", "server");

if (!existsSync(src)) {
  console.error(`[sphior-vscode] LSP server not found: ${src}`);
  console.error("  → run `npm run build` in packages/sphior-scan first.");
  process.exit(1);
}

mkdirSync(destDir, { recursive: true });
cpSync(src, join(destDir, "server.cjs"));
console.log("[sphior-vscode] server.cjs bundled into server/");
