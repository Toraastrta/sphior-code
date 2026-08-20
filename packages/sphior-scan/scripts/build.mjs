/**
 * build.mjs — CLI と LSP サーバを esbuild でバンドル
 *
 * engine は extensionless な相対 import（Next 由来）なので Node 実行には
 * バンドルが必要。
 *  - CLI    : ESM（source の hashbang を保持）。外部依存なし。
 *  - LSP    : CJS(.cjs)（vscode-languageserver は CJS 依存を含むため CJS で解決）。
 */

import { build } from "esbuild";
import { rmSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });

const common = { bundle: true, platform: "node", target: "node18", logLevel: "warning" };

// CLI — ESM
await build({
  ...common,
  entryPoints: { cli: "src/cli.ts" },
  outdir: "dist",
  format: "esm",
});

// LSP サーバ — CJS（node dist/server.cjs --stdio）
await build({
  ...common,
  entryPoints: { server: "src/lsp/server.ts" },
  outdir: "dist",
  format: "cjs",
  outExtension: { ".js": ".cjs" },
});

console.log("[sphior-scan] built dist/cli.js, dist/server.cjs");
