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

// legalComments: "eof" — 依存（MIT 等）の著作権表示をバンドル末尾に残す。
// esbuild の既定はこれらを捨ててしまうが、MIT は「複製物に著作権表示を含めること」を
// 条件にしているので、バンドル配布では明示的に保持する必要がある。
// 監査証跡を売っている以上、自分たちの配布物のライセンス順守が崩れているのは筋が通らない。
const common = {
  bundle: true, platform: "node", target: "node18", logLevel: "warning",
  legalComments: "eof",
};

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
