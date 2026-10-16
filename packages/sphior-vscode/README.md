# SPHIOR CODE for VS Code

Deterministic **secrets** + **insecure-pattern (CWE)** detection, right in your editor.

- **No AI, no source upload.** Detection is 100% deterministic and runs locally via a bundled
  language server (`@sphior/scan`). Your code never leaves your machine.
- **Same engine as SPHIOR's service.** The detection engine here is the one SPHIOR runs server-side,
  so what you see in the editor matches what a connected repository reports. The extension itself
  is entirely local — connecting a repository to SPHIOR is optional and separate.
- **Fix with your own AI.** SPHIOR hands findings to your existing AI assistant (Copilot / Cursor /
  Claude Code) over MCP (`get_fix_context`) — SPHIOR does not generate code for you.

## What it flags

- Hard-coded secrets / API keys (provider signatures + entropy, masked previews only)
- Insecure code patterns mapped to CWE (eval, command injection, XSS sinks, disabled TLS
  verification, weak crypto, unsafe deserialization, …)

Supported languages: **JavaScript, TypeScript (+ JSX/TSX), Python, Go, PHP, Ruby, Java, C#, Rust,
Kotlin, C, C++, Scala, Swift** — 14 languages, analysed with real parsers (tree-sitter), not just regex.

## Let your AI fix them

Each finding’s diagnostic carries the deterministic *why* + remediation steps, so **Copilot / Cursor
/ Claude** can fix it directly. Use the lightbulb 💡 **“SPHIOR: Fix with your AI”** to copy a
ready-to-paste fix prompt. To make your agent fix SPHIOR findings **automatically**, see
[AI-AUTOFIX.md](./AI-AUTOFIX.md).

## Build (from source)

```bash
# 1. build the shared engine + LSP server
cd ../sphior-scan && npm install && npm run build
# 2. build the extension
cd ../sphior-vscode && npm install && npm run build
```

The extension bundles the deterministic engine — the single source of truth is
`packages/sphior-scan/src/engine` (synced into `@sphior/scan` at build time; no drift).
