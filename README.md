# SPHIOR CODE

Deterministic secrets and insecure-pattern (CWE) detection for **VS Code**, **JetBrains IDEs**, the
command line, and CI — running entirely on your machine.

**No AI. No source upload. No telemetry.** The same input always produces the same findings.

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/sphior.sphior-code?label=VS%20Code)](https://marketplace.visualstudio.com/items?itemName=sphior.sphior-code)
[![Open VSX](https://img.shields.io/open-vsx/v/sphior/sphior-code?label=Open%20VSX)](https://open-vsx.org/extension/sphior/sphior-code)
[![JetBrains Plugin](https://img.shields.io/jetbrains/plugin/v/33696-sphior-code?label=JetBrains)](https://plugins.jetbrains.com/plugin/33696-sphior-code)
[![npm](https://img.shields.io/npm/v/%40sphior%2Fscan?label=npm)](https://www.npmjs.com/package/@sphior/scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Try it in 10 seconds

No install, no account, no config:

```bash
npx @sphior/scan run .
```

```
SPHIOR CODE: 3 findings (critical=1 high=1 medium=1 low=0) 1 files scanned
             engine=0.1.0 ruleset=2026.10.20-23
```

In a terminal you get a table sorted by severity. Piped, you get SARIF — so
`npx @sphior/scan run . | jq` works, and `--sarif out.sarif` is accepted by GitHub
code scanning.

Give findings to the coding assistant you already use, via MCP:

```bash
npx sphior-code-mcp        # or add it from the MCP registry: io.github.Toraastrta/sphior-code-mcp
```

Editors: [VS Code](https://marketplace.visualstudio.com/items?itemName=sphior.sphior-code) ·
[JetBrains](https://plugins.jetbrains.com/plugin/33696-sphior-code) ·
[Open VSX](https://open-vsx.org/extension/sphior/sphior-code)

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
- **Insecure code patterns mapped to CWE** — 84 rules covering command injection, `eval`,
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

Detection is regression-gated in CI against a fixed corpus: a rule change that loses a detection,
or that starts firing on a known-safe variant, fails the build rather than shipping quietly.

## What it does not do

- **It does not chase injection recall in static analysis.** Proving that untrusted input
  reaches a sink across a whole codebase is what dynamic testing is for. We would rather be
  silent than guess.
- **It is not a penetration test.** Auditors do not accept scanner output as one, and we do
  not present it as one.
- **It does not judge compliance.** It records facts; it does not decide whether you pass.
- **It does not see your runtime.** A vulnerability in the language runtime or in a server you
  deploy is invisible to a source-code scanner.

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
SPHIOR CODE: 4 findings (critical=1 high=3 medium=0 low=0) engine=0.1.0 ruleset=2026.10.20-23
```

SARIF output (`--sarif out.sarif`) is accepted by GitHub code scanning and most CI dashboards.

## Privacy

The extensions bundle the language server and start it as a local process. There is no network
client in the shipped engine — no telemetry, no analytics, no phone-home.

**Verify it yourself.** `git grep 'fetch('` over `packages/sphior-scan/src` does return hits, and
all of them are one of two things: the *detection rules* that look for `fetch`/`axios` as an SSRF
sink in **your** code, and string builders for advisory links (`https://osv.dev/...`) that are
printed, never requested. There is no call site. The same holds for the bundled `server.cjs` in a
published artifact.

Secret values are never stored or transmitted. Findings carry a masked preview
(`AKI…TY`) and a SHA-256 of the surrounding snippet, never the secret itself.

## Evidence records

`packages/sphior-scan/src/engine/evidence` implements the tamper-evident side: canonical JSON
(RFC 8785), SHA-256 fingerprints, a per-tenant hash chain, and Merkle roots for batch anchoring.
This is what lets a scan result be verified later by someone who does not trust the party that
produced it.

The verification logic is here in the open on purpose — evidence that only its author can check
is not evidence.

## Where this stops

The engine seals each scan locally, which makes a single result verifiable. What it cannot do
on its own is keep the **history**: what was scanned last month, which findings were fixed,
how long they took, and what was deliberately left out of scope. That record is what an
auditor actually asks for, and it has to live somewhere that outlasts a laptop.

[SPHIOR](https://sphior.com) is that place — the same engine, with the history kept and
independently verifiable. The scanner here stays free and unlimited either way; nothing is
held back from it to make the hosted side look better.

## Related

- [`@sphior/scan`](https://www.npmjs.com/package/@sphior/scan) — engine + CLI + language server
- [`sphior-code-mcp`](https://www.npmjs.com/package/sphior-code-mcp) — MCP server
  (`io.github.Toraastrta/sphior-code-mcp`)
- [SPHIOR](https://sphior.com) — the hosted service this engine also powers

## License

MIT — see [LICENSE](LICENSE).
