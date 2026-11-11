# SPHIOR CODE for JetBrains

Deterministic **secrets** + insecure-pattern (**CWE**) detection for all JetBrains IDEs
(IntelliJ IDEA, PyCharm, WebStorm, GoLand, Rider, …), via LSP4IJ.

- **No AI, no source upload.** Detection is 100% deterministic and runs locally through a bundled
  language server (`@sphior/scan`). Your code never leaves your machine.
- **Same engine as the CLI and VS Code.** The engine lives in `packages/sphior-scan/src/engine`
  and is bundled at build time. Each release bundles the ruleset current at that time; the
  version is listed in the [repository README](https://github.com/Toraastrta/sphior-code#versions).
- **Fix with your own AI.** Findings are handed to your existing AI assistant over MCP —
  SPHIOR does not generate code for you.

## Requirements

- **Node.js** on `PATH` (or set `SPHIOR_NODE_PATH`) — the language server runs on Node.
- **LSP4IJ** plugin (declared as a dependency; the Marketplace installs it automatically).

## Languages

JavaScript, TypeScript (+ JSX/TSX), Python, Go, PHP, Ruby, Java, C#, Rust, Kotlin, C, C++, Scala,
Swift — matched by file name pattern, so it works in every JetBrains IDE from 2024.2 regardless of
bundled language support.

## Let your AI fix them

Each finding’s diagnostic carries the deterministic *why* + remediation steps, so **JetBrains AI /
Copilot** can fix it directly from the diagnostic. To make your agent fix SPHIOR findings
**automatically**, see [../sphior-vscode/AI-AUTOFIX.md](../sphior-vscode/AI-AUTOFIX.md)
(the agent-rule snippets and MCP setup apply to any IDE).

To build it yourself, see [Building from source](https://github.com/Toraastrta/sphior-code#repository-layout-and-building-from-source).
