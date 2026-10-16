#!/usr/bin/env node
/**
 * cli.ts — `sphior-scan run <dir>` の bin エントリ
 *
 * 起動時に Python AST バックエンド(tree-sitter)を init（失敗は regex fallback）し、
 * 決定論エンジンの runCli を実行する。出力: SARIF / findings / fix-context。
 */

import { runCli } from "./engine/index";
import { initPython } from "./python-ast";
import { initGo } from "./go-ast";
import { initPhp } from "./php-ast";
import { initRuby } from "./ruby-ast";
import { initJava } from "./java-ast";
import { initCsharp } from "./csharp-ast";
import { initRust } from "./rust-ast";
import { initKotlin } from "./kotlin-ast";
import { initC, initCpp } from "./cfamily-ast";
import { initScala } from "./scala-ast";
import { initSwift } from "./swift-ast";

async function main(): Promise<void> {
  await Promise.all([initPython(), initGo(), initPhp(), initRuby(), initJava(), initCsharp(), initRust(), initKotlin(), initC(), initCpp(), initScala(), initSwift()].map((p) => p.catch(() => {})));
  const res = runCli(process.argv.slice(2), {
    cwd: process.cwd(),
    log: (m) => console.log(m),              // データ（SARIF）
    logErr: (m) => console.error(m),         // 診断（サマリ・警告・ヒント）
    // 端末なら人が読む形、パイプ/リダイレクトなら SARIF（`| jq` を壊さない）
    isTty: Boolean(process.stdout.isTTY),
  });
  process.exit(res.exitCode);
}

void main();
