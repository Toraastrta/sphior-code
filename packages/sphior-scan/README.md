# @sphior/scan

SPHIOR CODE の**決定論スキャンエンジン**（secrets + insecure-pattern/CWE + SCA）を、
CLI・LSP（VS Code / JetBrains）・CI で共有する配布パッケージ。

- **自前 AI ゼロ**：検知は 100% 決定論（正規表現/エントロピー/AST・taint/OSV）。再現可能・監査グレード。
- **One engine**：`src/engine` が検出エンジンの本体。CLI・LSP（VS Code / JetBrains）・CI が同じコードを共有する。
- **ソース非送信**：LSP はローカルで診断を返す。修正は顧客の AI へ MCP（`get_fix_context`）で finding を渡す（§0.6）。

## CLI

```bash
sphior-scan run <dir> [--sarif out.sarif] [--json out.json] [--fix-context fc.json] [--fail-on high]
```

## LSP

```bash
node dist/server.js --stdio
```

VS Code 拡張 / JetBrains プラグインがこの LSP に接続し、編集中のファイルの
secrets・危険パターンを即時に診断表示する。

## Build

```bash
npm install
npm run typecheck   # sync + tsc --noEmit
npm run build       # sync + esbuild → dist/cli.js, dist/server.js
```

`src/engine` は同期生成物（gitignore）。単一ソースは `../../src/lib/scan`。
