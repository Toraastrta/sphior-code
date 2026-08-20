# sphior-code-mcp

Official **Model Context Protocol (MCP)** server for **SPHIOR CODE** — surface security findings from your GitHub repositories directly inside any MCP-compatible AI coding assistant.

[![npm version](https://img.shields.io/npm/v/sphior-code-mcp.svg)](https://www.npmjs.com/package/sphior-code-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What this gives you

Your AI assistant can now answer questions like:

- *"What are the highest-severity vulnerabilities in my code right now?"*
- *"Show me the fix for finding `abc-123`."*
- *"Mark this SQL injection alert as resolved — I just fixed it."*
- *"What's our overall security posture this month?"*

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

## Configuration

Set your API key from [sphior.com/account/api](https://sphior.com/account/api):

```bash
export SPHIOR_API_KEY=sk_live_xxxxxxxxxxxx
```

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SPHIOR_API_KEY`  | ✅ Yes | — | Bearer token from your SPHIOR Code account |
| `SPHIOR_API_BASE` | No | `https://sphior.com/api/v1` | Override for self-hosted / regional deployments |
| `SPHIOR_TIMEOUT`  | No | `30000` | Request timeout in ms (1000–300000) |
| `SPHIOR_DEBUG`    | No | `false` | Enable verbose logging to stderr |

## Example config (Cursor / Claude Code / VS Code style)

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

For **GitHub Copilot in VS Code**, use `"servers"` instead of `"mcpServers"`:

```json
{
  "servers": {
    "sphior-code": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "sphior-code-mcp"],
      "env": {
        "SPHIOR_API_KEY": "sk_live_xxxxxxxxxxxx"
      }
    }
  }
}
```

## Tools exposed

| Tool | Purpose |
|---|---|
| `list_findings` | List vulnerabilities (filter by severity / status / limit) |
| `get_finding` | Full details for one finding (CVSS, CWE, file path, fix hint) |
| `get_security_summary` | Posture overview (counts by severity, last scan, repos monitored) |
| `resolve_finding` | Mark as fixed |
| `mark_false_positive` | Mark as not exploitable |
| `health_check` | Verify connection + auth |

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
