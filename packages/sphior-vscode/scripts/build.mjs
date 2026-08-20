/**
 * build.mjs — VS Code 拡張本体を esbuild でバンドル（CJS・vscode は host 提供）
 */

import { build } from "esbuild";
import { rmSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });

await build({
  entryPoints: ["src/extension.ts"],
  outfile: "dist/extension.js",
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node18",
  external: ["vscode"], // VS Code 本体が提供
  logLevel: "warning",
});

console.log("[sphior-vscode] built dist/extension.js");
