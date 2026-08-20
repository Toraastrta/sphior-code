/**
 * server.ts — SPHIOR CODE Language Server（VS Code / JetBrains 共通土台）
 *
 * 設計 §4.4 / P6。開いている・編集中のドキュメントを決定論エンジンで
 * スキャンし、secrets / insecure-pattern(CWE) を診断として即時に返す。
 * ソースコードは端末外へ送らない（ローカル完結）。
 *
 * 「入れておくだけで顧客の AI が直す」ビジョンのため、診断には決定論の
 * 修正ガイド（why + 手順 + CWE リンク）と fix-context を載せる。host の AI
 * （Copilot/Cursor/JetBrains AI）が診断から正確に直せる。加えて Quick Fix
 * コードアクション（sphior.showFix）で AI 向けプロンプトを提供する。
 *
 * 1 engine を CLI/CI と共有（src/engine は sync 生成）。
 */

import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  DiagnosticSeverity,
  TextDocumentSyncKind,
  CodeActionKind,
  type Diagnostic,
  type InitializeResult,
  type CodeAction,
  type CodeActionParams,
} from "vscode-languageserver/node";
import { TextDocument } from "vscode-languageserver-textdocument";
import { runScan, buildFixContext } from "../engine/index";
import type { Severity, FixContext } from "../engine/index";
import { initPython } from "../python-ast";
import { initGo } from "../go-ast";
import { initPhp } from "../php-ast";
import { initRuby } from "../ruby-ast";
import { initJava } from "../java-ast";
import { initCsharp } from "../csharp-ast";
import { initRust } from "../rust-ast";
import { initKotlin } from "../kotlin-ast";
import { initC, initCpp } from "../cfamily-ast";
import { initScala } from "../scala-ast";
import { initSwift } from "../swift-ast";

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);

const SEVERITY_MAP: Record<Severity, DiagnosticSeverity> = {
  critical: DiagnosticSeverity.Error,
  high: DiagnosticSeverity.Error,
  medium: DiagnosticSeverity.Warning,
  low: DiagnosticSeverity.Information,
  info: DiagnosticSeverity.Hint,
};

connection.onInitialize((): InitializeResult => ({
  capabilities: {
    textDocumentSync: TextDocumentSyncKind.Full,
    codeActionProvider: { codeActionKinds: [CodeActionKind.QuickFix] },
  },
  serverInfo: { name: "sphior-scan", version: "0.1.0" },
}));

/** 診断の data に載せる（コードアクション/エージェントが消費）。 */
interface SphiorDiagnosticData {
  fingerprint: string;
  cwe?: string;
  fixContext: FixContext;
}

/** ドキュメントを決定論スキャンして「AI が直せる」リッチ診断へ変換。 */
function scanDocument(doc: TextDocument): Diagnostic[] {
  const path = doc.uri.replace(/^file:\/\//, "");
  const { findings } = runScan({ files: [{ path, text: doc.getText() }] });

  return findings.map((f) => {
    const fc = buildFixContext(f);
    // message に「なぜ + どう直すか」を載せる → host の AI がそのまま正確に修正できる
    const steps = fc.remediation_steps.slice(0, 3).join(" ");
    const data: SphiorDiagnosticData = { fingerprint: f.fingerprint, cwe: f.cwe, fixContext: fc };
    return {
      severity: SEVERITY_MAP[f.severity] ?? DiagnosticSeverity.Information,
      range: {
        start: { line: Math.max(0, f.location.start_line - 1), character: Math.max(0, f.location.start_col - 1) },
        end: { line: Math.max(0, f.location.end_line - 1), character: Math.max(0, f.location.end_col - 1) },
      },
      message: `${f.title}: ${fc.why} Fix: ${steps}`,
      source: "SPHIOR",
      code: f.rule_id,
      codeDescription: f.references && f.references[0] ? { href: f.references[0] } : undefined,
      data,
    };
  });
}

documents.onDidChangeContent((change) => {
  connection.sendDiagnostics({ uri: change.document.uri, diagnostics: scanDocument(change.document) });
});

documents.onDidClose((e) => {
  connection.sendDiagnostics({ uri: e.document.uri, diagnostics: [] });
});

// Quick Fix: SPHIOR 診断ごとに「あなたの AI で直す」アクションを提供。
// クライアント（拡張）が sphior.showFix を実行し、AI 向けプロンプトを用意する。
connection.onCodeAction((params: CodeActionParams): CodeAction[] => {
  const actions: CodeAction[] = [];
  for (const diag of params.context.diagnostics) {
    if (diag.source !== "SPHIOR" || !diag.data) continue;
    const data = diag.data as SphiorDiagnosticData;
    if (!data.fixContext) continue;
    actions.push({
      title: `SPHIOR: Fix "${data.fixContext.title}" with your AI`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [diag],
      isPreferred: true,
      command: {
        title: "SPHIOR: prepare AI fix",
        command: "sphior.showFix",
        arguments: [data.fixContext],
      },
    });
  }
  return actions;
});

// Python AST(tree-sitter)を有効化してから listen（失敗は regex fallback・数百 ms）
async function start(): Promise<void> {
  await Promise.all([initPython(), initGo(), initPhp(), initRuby(), initJava(), initCsharp(), initRust(), initKotlin(), initC(), initCpp(), initScala(), initSwift()].map((p) => p.catch(() => {})));
  documents.listen(connection);
  connection.listen();
}
void start();
