# sphior-code-mcp

Official **Model Context Protocol (MCP)** server for **SPHIOR CODE** — find security issues in your code and let your own AI assistant fix them, inside any MCP-compatible client.

**No account needed to start.** With no API key set, the server scans your local workspace with the
bundled deterministic engine and hands the findings to your AI agent. Add an API key later if you
want tamper-evident evidence, history and GRC integrations.

[![npm version](https://img.shields.io/npm/v/sphior-code-mcp.svg)](https://www.npmjs.com/package/sphior-code-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What this gives you

Your AI assistant can now answer questions like:

- *"Scan this project and fix the critical issues."*  ← works with no account
- *"What are the highest-severity vulnerabilities in my code right now?"*
- *"Show me the fix for finding `abc-123`."*
- *"Mark this SQL injection alert as resolved — I just fixed it."*  (requires an API key)
- *"What's our overall security posture this month?"*  (requires an API key)

…using **live data from SPHIOR's scanning engine** — deterministic SAST (secrets + CWE patterns,
analysed with real parsers across 14 languages) and SCA powered by OSV.dev. **No AI is involved in
detection**, so the same code always produces the same findings.

## Supported clients

This is a standard MCP stdio server, so it works with **any MCP-compatible client**:

| Client | Config location | Setup |
|---|---|---|
| **Cursor** | `~/.cursor/mcp.json` | [Add MCP](https://cursor.sh/) |
| **Claude Code** | `~/.claude.json` | `claude mcp add sphior-code -- npx sphior-code-mcp` |
| **VS Code** | `~/.config/Code/User/settings.json` (`mcp.servers`) | Built-in MCP |
| **GitHub Copilot (VS Code)** | `.vscode/mcp.json` | Native MCP |
| **Cline** (VS Code extension) | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | Settings UI |
| **Continue** (VS Code extension) | `~/.continue/config.yaml` | `mcpServers:` section |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | Settings UI |
| **Zed** | `~/.config/zed/settings.json` (`context_servers`) | Native MCP |
| **JetBrains AI Assistant** (2024.3+) | Settings → Tools → AI Assistant → MCP | Built-in |

## Installation

```bash
# No install needed — use npx
npx -y sphior-code-mcp

# Or install globally
npm install -g sphior-code-mcp
sphior-code-mcp
```

## Two modes

| | **Local** (default) | **Cloud** |
|---|---|---|
| Setup | nothing — just run it | set `SPHIOR_API_KEY` |
| What it scans | your local workspace | repositories connected to SPHIOR |
| Tools available | `get_fix_context`, `health_check` | all 8 tools |
| Source code leaves your machine | **never** | **never** |
| Tamper-evident evidence / history / GRC push | — | ✅ |

In **local** mode the server runs the same deterministic engine that powers the editor extensions
(secrets + CWE patterns + taint analysis across 14 languages, parsed with real grammars) against the
directory your client launched it in, then returns remediation guidance your agent can act on.
It never contacts SPHIOR's servers.

Cloud-only tools return a clear message explaining what they need, rather than failing silently.

## Configuration

Nothing is required to start. To unlock cloud features, set an API key from
[sphior.com/account/api](https://sphior.com/account/api):

```bash
export SPHIOR_API_KEY=sk_live_xxxxxxxxxxxx
```

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SPHIOR_API_KEY`  | No | — | Bearer token. Omit for local mode; set it for cloud mode |
| `SPHIOR_WORKSPACE` | No | current directory | Directory to scan in local mode |
| `SPHIOR_API_BASE` | No | `https://sphior.com/api/v1` | Override for self-hosted / regional deployments |
| `SPHIOR_TIMEOUT`  | No | `30000` | Request timeout in ms (1000–300000) |
| `SPHIOR_DEBUG`    | No | `false` | Enable verbose logging to stderr |

## Example config (Cursor / Claude Code / VS Code style)

**Local mode — copy, paste, done.** No account, no key.

```json
{
  "mcpServers": {
    "sphior-code": {
      "command": "npx",
      "args": ["-y", "sphior-code-mcp"]
    }
  }
}
```

Claude Code users can skip the file entirely:

```bash
claude mcp add sphior-code -- npx sphior-code-mcp
```

Then ask your agent: *"Scan this project and fix the critical issues."*

**Cloud mode** — add the key to the same block:

```json
{
  "mcpServers": {
    "sphior-code": {
      "command": "npx",
      "args": ["-y", "sphior-code-mcp"],
      "env": {
        "SPHIOR_API_KEY": "sk_live_xxxxxxxxxxxx"
      }
    }
  }
}
```

For **GitHub Copilot in VS Code**, use `"servers"` instead of `"mcpServers"` (the `env` block is
optional here too):

```json
{
  "servers": {
    "sphior-code": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "sphior-code-mcp"]
    }
  }
}
```

## Tools exposed

| Tool | Mode | Purpose |
|---|---|---|
| `get_fix_context` | **local** + cloud | Remediation guidance your agent acts on — why it matters, exact location, steps, references. **Source code is never sent**; the agent opens the file in your own workspace |
| `health_check` | **local** + cloud | Verify the server is up (and auth, in cloud mode) |
| `list_findings` | cloud | List vulnerabilities (filter by severity / status / limit) |
| `get_finding` | cloud | Full details for one finding (CVSS, CWE, file path, fix hint) |
| `get_security_summary` | cloud | Posture overview (counts by severity, last scan, repos monitored) |
| `resolve_finding` | cloud | Mark as fixed |
| `mark_false_positive` | cloud | Mark as not exploitable |
| `verify_evidence` | cloud | Independently verify the tamper-evident evidence chain (for auditors) |

`get_fix_context` accepts `path` in local mode to scan a directory other than the one your client
launched the server in.

## Resources exposed

- `sphior-code://summary` — JSON snapshot of current posture
- `sphior-code://findings/{id}` — full detail per finding (auto-listed for open findings)

## Reliability

- **Exponential backoff retry** on 5xx / network errors (3 attempts)
- **30-second request timeout** (configurable)
- **Graceful degradation** — auth errors fail fast, server errors retry
- **Structured errors** with actionable hints
- **stderr-only logging** (stdout is reserved for MCP protocol)

## Development

```bash
# In this directory
npm install
npm run build
# Local mode — no key needed
node bin/sphior-code-mcp.js

# Cloud mode
SPHIOR_API_KEY=sk_test_xxx node bin/sphior-code-mcp.js
# Type a JSON-RPC request to test
```

## License

MIT © SPHIOR Security

## Links

- 🌐 [SPHIOR Code](https://sphior.com/code)
- 📖 [API Reference](https://sphior.com/docs/api)
- 🐛 [Report issues](https://github.com/sphior/code-mcp/issues)
- 🔑 [Get an API key](https://sphior.com/account/api)
