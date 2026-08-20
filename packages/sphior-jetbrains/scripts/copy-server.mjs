/**
 * copy-server.mjs — @sphior/scan の LSP サーバをプラグイン resources へ同梱
 *
 * server.cjs を src/main/resources/server/ にコピーし、jar にバンドルする
 * （実行時に SphiorLspServer が一時展開して node で spawn）。
 * @sphior/scan は事前に `npm run build` 済みであること。
 */

import { cpSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "..", "sphior-scan", "dist", "server.cjs");
const destDir = join(here, "..", "src", "main", "resources", "server");

if (!existsSync(src)) {
  console.error(`[sphior-jetbrains] LSP server not found: ${src}`);
  console.error("  → run `npm run build` in packages/sphior-scan first.");
  process.exit(1);
}

mkdirSync(destDir, { recursive: true });
cpSync(src, join(destDir, "server.cjs"));
console.log("[sphior-jetbrains] server.cjs bundled into src/main/resources/server/");
