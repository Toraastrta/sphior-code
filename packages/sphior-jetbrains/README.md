# SPHIOR CODE for JetBrains

Deterministic **secrets** + insecure-pattern (**CWE**) detection for all JetBrains IDEs
(IntelliJ IDEA, PyCharm, WebStorm, GoLand, Rider, …), via LSP4IJ.

- **No AI, no source upload.** Detection is 100% deterministic and runs locally through a bundled
  language server (`@sphior/scan`). Your code never leaves your machine.
- **Same engine as CI + VS Code.** The single source of truth is `packages/sphior-scan/src/engine`
  (synced into `@sphior/scan` at build time; no drift).
- **Fix with your own AI.** Findings are handed to your existing AI assistant over MCP —
  SPHIOR does not generate code for you.

## Requirements

- **Node.js** on `PATH` (or set `SPHIOR_NODE_PATH`) — the language server runs on Node.
- **LSP4IJ** plugin (declared as a dependency; the Marketplace installs it automatically).

## Languages

JavaScript, TypeScript (+ JSX/TSX), Python — matched by file name pattern, so it works in
every JetBrains IDE regardless of bundled language support.

## Let your AI fix them

Each finding’s diagnostic carries the deterministic *why* + remediation steps, so **JetBrains AI /
Copilot** can fix it directly from the diagnostic. To make your agent fix SPHIOR findings
**automatically**, see [../sphior-vscode/AI-AUTOFIX.md](../sphior-vscode/AI-AUTOFIX.md)
(the agent-rule snippets and MCP setup apply to any IDE).

See [BUILD.md](./BUILD.md) for building and publishing to the JetBrains Marketplace.
