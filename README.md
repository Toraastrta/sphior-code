# SPHIOR CODE

Deterministic secrets and insecure-pattern (CWE) detection for **VS Code**, **JetBrains IDEs**, the
command line, and CI — running entirely on your machine.

**No AI. No source upload. No telemetry.** The same input always produces the same findings.

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/sphior.sphior-code?label=VS%20Code)](https://marketplace.visualstudio.com/items?itemName=sphior.sphior-code)
[![Open VSX](https://img.shields.io/open-vsx/v/sphior/sphior-code?label=Open%20VSX)](https://open-vsx.org/extension/sphior/sphior-code)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why this exists

Most code scanners either ship your source to a server, or ask a language model what it thinks.
Both make results hard to trust: you cannot reproduce them, and you cannot explain them to an
auditor.

This one is **deterministic**. Every finding comes from a rule with a stable id, a CWE mapping, and
a fingerprint derived from the code itself. Run it twice, get the same answer. Run it on someone
else's machine, get the same answer.

## What it finds

- **Hard-coded secrets** — provider signatures plus entropy checks, across 36 rules
  (AWS, GCP, GitHub, Stripe, Slack, OpenAI, Anthropic, …). Only masked previews are ever emitted;
  raw values never leave the process.
- **Insecure code patterns mapped to CWE** — 83 rules covering command injection, `eval`,
  XSS sinks, disabled TLS verification, weak crypto, unsafe deserialization, path traversal,
  SSRF, and more.
- **Data-flow (taint) analysis for JavaScript/TypeScript** — tracks untrusted input from source
  to sink, so `db.query("… " + req.query.id)` is reported as SQL injection rather than a generic
  string-concatenation warning.

### Languages

JavaScript, TypeScript (+ JSX/TSX), Python, Go, PHP, Ruby, Java, C#, Rust, Kotlin, C, C++,
Scala, Swift — **14 languages**, parsed with real grammars (tree-sitter), not regex alone.

Regex rules are used only where a parser adds nothing. When a language has an AST backend,
the parser-based results take precedence and the regex equivalents are suppressed, which keeps
false positives down.

## Repository layout

```
packages/
├── sphior-scan/       Detection engine + language server + CLI  (@sphior/scan)
│   ├── src/engine/      rules, taint analysis, evidence records, SARIF output
│   ├── src/*-ast.ts     tree-sitter backends, registered at runtime per language
│   └── src/lsp/         Language Server Protocol implementation
├── sphior-vscode/     VS Code extension  (bundles the language server)
├── sphior-jetbrains/  JetBrains plugin   (LSP4IJ + the same language server)
└── code-mcp/          MCP server, surfaces findings to AI coding assistants
```

**One engine, many surfaces.** The editor, the CLI and CI all execute the identical detection
code — there is no "editor version" that behaves differently from the CI version.

## Build from source

Requires Node.js 18+.

```bash
# 1. engine + language server + CLI
cd packages/sphior-scan && npm install && npm run build

# 2a. VS Code extension (bundles the server produced above)
cd ../sphior-vscode && npm install && npm run build

# 2b. JetBrains plugin (requires JDK 21)
cd ../sphior-jetbrains && ./gradlew buildPlugin
```

The Gradle build syncs the language server produced in step 1 before packaging, so there
is no copy step to remember — it fails rather than bundling a stale server.

### Try the CLI

```bash
node packages/sphior-scan/dist/cli.js run ./your-project --json findings.json
```

```
SPHIOR CODE: 4 findings (critical=1 high=3 medium=0 low=0) engine=0.1.0 ruleset=2026.07.12-22
```

SARIF output (`--sarif out.sarif`) is accepted by GitHub code scanning and most CI dashboards.

## Privacy

The extensions bundle the language server and start it as a local process. There is no network
client in the shipped engine — no telemetry, no analytics, no phone-home. You can verify this:
search this repository for `fetch(`, or inspect the bundled `server.cjs` in a published artifact.

Secret values are never stored or transmitted. Findings carry a masked preview
(`AKI…TY`) and a SHA-256 of the surrounding snippet, never the secret itself.

## Evidence records

`packages/sphior-scan/src/engine/evidence` implements the tamper-evident side: canonical JSON
(RFC 8785), SHA-256 fingerprints, a per-tenant hash chain, and Merkle roots for batch anchoring.
This is what lets a scan result be verified later by someone who does not trust the party that
produced it.

The verification logic is here in the open on purpose — evidence that only its author can check
is not evidence.

## Related

- [SPHIOR](https://sphior.com) — the hosted service this engine also powers
- [`sphior-code-mcp`](https://www.npmjs.com/package/sphior-code-mcp) on npm

## License

MIT — see [LICENSE](LICENSE).
