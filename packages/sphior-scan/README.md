# @sphior/scan

Deterministic security scanner for source code — **hardcoded secrets** and
**insecure patterns (CWE)** — with no AI, no network and no source upload.

Detection is 100% deterministic (regex + entropy + AST/taint analysis), so the same code always
produces the same findings. The scan makes no network requests at all: your source never leaves
the machine it runs on, and it works offline.

```bash
npx @sphior/scan run ./src
```

## Install

```bash
# one-off
npx @sphior/scan run ./src

# or install globally
npm install -g @sphior/scan
sphior-scan run ./src
```

Requires Node.js 18 or newer.

## Usage

```
sphior-scan run <dir> [options]

Options:
  --sarif <file>         write SARIF 2.1.0 (GitHub code scanning, most CI tools)
  --json <file>          write raw findings as JSON
  --fix-context <file>   write finding context for an AI assistant to act on
  --fail-on <severity>   exit non-zero at or above this severity
                         (critical | high | medium | low)
```

SARIF is written to stdout as well, so it pipes cleanly:

```bash
sphior-scan run ./src --fail-on high
```

Exit code is `0` when nothing at or above `--fail-on` was found, non-zero otherwise —
which is what you want in CI.

### GitHub Actions

```yaml
- run: npx @sphior/scan run . --sarif results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## What it detects

| Category | How |
|---|---|
| Hardcoded secrets | Provider-specific patterns + entropy analysis. Well-known documentation placeholders are excluded, so example keys don't create noise. |
| Insecure patterns (CWE) | AST-based, including taint tracking from untrusted sources to dangerous sinks (SQL injection, XSS, command injection and similar). |

Dependency (SCA) scanning is **not** part of this CLI. The engine accepts SCA input, but the
`run` command only analyses source files. Dependency vulnerabilities are surfaced by SPHIOR CODE
on GitHub, which resolves lockfiles against the OSV database.

Findings carry a rule id, severity, CWE where applicable, and the exact file and line.

## Language server

The package also ships a Language Server Protocol server, so editors can show findings
inline while you type:

```bash
node node_modules/@sphior/scan/dist/server.cjs --stdio
```

The SPHIOR CODE extensions for VS Code and JetBrains connect to this server. Everything is
analysed locally — nothing is sent anywhere.

## Privacy

The scanner reads your files and reports what it found. It makes no network requests: no source
upload, no telemetry, no language model, no account. It runs correctly with networking disabled.

## Links

- Product: <https://sphior.com/code>
- Issues: <https://github.com/Toraastrta/Sphior/issues>

## License

MIT — see [LICENSE](./LICENSE).
