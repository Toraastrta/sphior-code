# sphior-ai-governance-mcp

Official **Model Context Protocol (MCP)** server for **SPHIOR AI Governance**.

Let your AI agent (Claude, Cursor, Cline, Windsurf, Zed, VS Code, …) record its own executions as
**tamper-evident, independently verifiable evidence** you can retain for **ISO 42001 / EU AI Act / SOC 2**.

Only **hashes and metadata** are stored (`hash_only`) — never your prompts or outputs unless you include them.

> Records **supporting evidence**. Does not assert compliance, pass/fail, or an audit opinion.

## Tools

| Tool | What it does |
|---|---|
| `record_ai_execution` | Record one AI execution (actor, model, provider, policy_decision, tokens, cost, latency, trace_id, …) |
| `record_ai_executions` | Record up to 200 executions in one call |

## Setup

Create an ingestion token under **Settings** at [sphior.com/app](https://sphior.com/app?settings=aiingest).
Without a token the server still starts, and its tools explain how to get one; nothing is recorded until it is set.

### Claude Desktop / Claude Code (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "sphior-ai-governance": {
      "command": "npx",
      "args": ["-y", "sphior-ai-governance-mcp"],
      "env": { "SPHIOR_AIGOV_TOKEN": "<your-token>" }
    }
  }
}
```

### Cursor / Cline / Windsurf / Zed

Add an MCP server with command `npx -y sphior-ai-governance-mcp` and env `SPHIOR_AIGOV_TOKEN=<your-token>`.

## Environment variables

| Var | Required | Default |
|---|---|---|
| `SPHIOR_AIGOV_TOKEN` | yes | — |
| `SPHIOR_AIGOV_ENDPOINT` | no | `https://sphior.com/api/ai-governance/ingest` |
| `SPHIOR_TIMEOUT` | no | `30000` (ms) |
| `SPHIOR_DEBUG` | no | `false` |

## What SPHIOR does with it

Each event is canonicalized (RFC 8785 JCS), hashed (SHA-256), chained, and periodically anchored to an
append-only, independently verifiable record. You and your auditor can verify integrity with the open
`sphior-verify` tool and standard timestamp tooling — without trusting SPHIOR.

Prefer plain code over an MCP agent? POST the same events directly to the ingestion endpoint — see the
[AI governance API reference](https://sphior.com/docs/ai-governance).

## License

Apache-2.0
