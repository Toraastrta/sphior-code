/**
 * ast-backend.ts — 言語別 AST 検出の pluggable レジストリ（純 TS・多言語）
 *
 * tree-sitter を要する言語（Python/Go/Ruby/PHP…）の AST/taint は engine core や
 * Next.js アプリ の静的依存にせず、@sphior/scan(CLI/LSP) が起動時に**動的登録**する。
 * engine core はこの依存ゼロのレジストリだけを参照し、登録があればその言語を
 * AST で高精度検出、無ければ regex にフォールバックする（本番ビルド無風）。
 */

import type { CanonicalFinding } from "../types";

export interface AstBackend {
  /** 対象拡張子（小文字・ドットなし）。 */
  exts: Set<string>;
  /** AST 検出。 */
  detect(path: string, text: string): CanonicalFinding[];
  /** この言語で AST が担当する rule id（regex 版を無効化）。 */
  coveredRuleIds: Set<string>;
}

const backends: AstBackend[] = [];

/** 言語バックエンドを登録（CLI/LSP 起動時）。 */
export function registerAstBackend(backend: AstBackend): void {
  backends.push(backend);
}

/** 拡張子に対応する登録済みバックエンド（無ければ null）。 */
export function getAstBackend(ext: string): AstBackend | null {
  for (const b of backends) if (b.exts.has(ext)) return b;
  return null;
}
