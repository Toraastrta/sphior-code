/**
 * extension.ts — SPHIOR CODE VS Code 拡張
 *
 * 設計 §4.4 / P7。バンドルした `@sphior/scan` の LSP サーバ（server.cjs）を
 * spawn し、編集中ファイルの secrets / insecure-pattern(CWE) を決定論スキャンで
 * 診断表示する。診断には修正ガイドと fix-context が載るため、host の AI
 * （Copilot/Cursor 等）がそのまま正確に直せる。
 *
 * さらに Quick Fix「SPHIOR: Fix with your AI」→ コマンド sphior.showFix が
 * AI 向けプロンプトを生成しクリップボードへ。ソースは端末外へ送らない。
 */

import * as path from "path";
import { commands, env, window, workspace, type ExtensionContext } from "vscode";
import {
  LanguageClient,
  TransportKind,
  type LanguageClientOptions,
  type ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

/** 決定論 fix-context（LSP server の buildFixContext 出力）。 */
interface FixContext {
  title: string;
  severity: string;
  cwe?: string;
  location: { path: string; start_line: number };
  why: string;
  remediation_steps: string[];
  agent_instructions: string;
}

/** 顧客の AI に貼るだけで直せる、そのままのプロンプトを組み立てる。 */
function buildAiPrompt(fc: FixContext): string {
  const steps = fc.remediation_steps.map((s, i) => `  ${i + 1}. ${s}`).join("\n");
  return [
    `Fix this security finding that SPHIOR detected deterministically (authoritative, not AI):`,
    ``,
    `- Finding: ${fc.title} [${fc.severity.toUpperCase()}${fc.cwe ? ` · ${fc.cwe}` : ""}]`,
    `- Location: ${fc.location.path}:${fc.location.start_line}`,
    `- Why it matters: ${fc.why}`,
    `- Remediation:`,
    steps,
    ``,
    fc.agent_instructions,
  ].join("\n");
}

export function activate(context: ExtensionContext): void {
  const output = window.createOutputChannel("SPHIOR CODE");
  context.subscriptions.push(output);

  // Quick Fix から呼ばれる: AI 向けプロンプトを作りクリップボードへ、詳細は Output へ。
  context.subscriptions.push(
    commands.registerCommand("sphior.showFix", async (fc: FixContext) => {
      if (!fc || !fc.title) return;
      const prompt = buildAiPrompt(fc);
      await env.clipboard.writeText(prompt);
      output.appendLine("─".repeat(60));
      output.appendLine(prompt);
      const pick = await window.showInformationMessage(
        `SPHIOR: fix guidance for "${fc.title}" copied — paste into your AI assistant (Copilot / Cursor / Claude).`,
        "Show details",
      );
      if (pick === "Show details") output.show(true);
    }),
  );

  if (!workspace.getConfiguration("sphior").get<boolean>("enable", true)) {
    return;
  }

  // バンドル済み LSP サーバ（build 時に @sphior/scan から server.cjs をコピー）
  const serverModule = context.asAbsolutePath(path.join("server", "server.cjs"));
  const serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.stdio },
    debug: { module: serverModule, transport: TransportKind.stdio },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "go" },
      { scheme: "file", language: "php" },
      { scheme: "file", language: "ruby" },
      { scheme: "file", language: "java" },
      { scheme: "file", language: "csharp" },
      { scheme: "file", language: "rust" },
      { scheme: "file", language: "kotlin" },
      { scheme: "file", language: "c" },
      { scheme: "file", language: "cpp" },
      { scheme: "file", language: "scala" },
      { scheme: "file", language: "swift" },
    ],
  };

  client = new LanguageClient("sphior", "SPHIOR CODE", serverOptions, clientOptions);
  void client.start();
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
