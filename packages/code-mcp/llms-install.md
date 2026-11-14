# Installing the SPHIOR CODE MCP server (for AI agents)

These steps are for an AI agent such as Cline that is setting this server up for a user.

## Do not clone or build this repository

The server is published on npm as `sphior-code-mcp` and runs with `npx`. Nothing needs to be
cloned, built or installed globally. Do not write a script to call the server directly; register
it in the MCP settings so the user can use it in every task.

## Add the server to the MCP settings

Add this entry to `mcpServers` in the MCP settings file the client actually reads, keeping any
servers that are already there. For Cline, that is `cline_mcp_settings.json`:

- **Cline 4.x** (current): `~/.cline/data/settings/cline_mcp_settings.json`, or under
  `$CLINE_DIR/data/settings/` when `CLINE_DIR` is set.
- **Older Cline**: the copy under the editor's global storage
  (`.../globalStorage/saoudrizwan.claude-dev/settings/`). Cline 4.x no longer reads it, so writing
  there has no effect.

If unsure, open the file from **MCP Servers → Configure** and edit that one. Do not create a new
file at a guessed path. After saving, confirm that `sphior-code` appears in the MCP Servers view.

```json
{
  "mcpServers": {
    "sphior-code": {
      "command": "npx",
      "args": ["-y", "sphior-code-mcp"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

- Requires Node.js 18 or later.
- No API key or account is needed. Without one, the server scans the local workspace with its
  bundled deterministic engine and source code never leaves the machine.
- Only if the user asks to connect their SPHIOR account, add
  `"env": { "SPHIOR_API_KEY": "<key starting with sk_live_>" }` to the entry. Ask the user for the
  key; never invent one.

## Check that it works

1. Call the `health_check` tool. Without a key it reports local mode and lists the usable tools.
2. Call `get_fix_context` with `path` set to a directory in the workspace to scan it. It returns
   each finding's file, line, CWE, why it matters and how to fix it.

Open the referenced file and apply the fix yourself; the server does not generate code. A human
should review the change before merge.
