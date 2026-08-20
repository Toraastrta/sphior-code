# Make your AI fix SPHIOR findings automatically

SPHIOR CODE detects issues **deterministically and locally** (no AI, no source upload) and exposes
them so your *existing* AI assistant fixes them. There are three levels — pick what fits your setup.

---

## Level 1 — Zero setup (works today)

Install this extension. Each finding appears as a diagnostic labeled **`SPHIOR`** whose message
already contains **why it matters + the exact remediation steps + a CWE link**.

- **Copilot / Cursor / JetBrains AI** all offer *“Fix with AI”* on any diagnostic → they read
  SPHIOR’s remediation and fix it correctly.
- Or use the **lightbulb 💡 → “SPHIOR: Fix with your AI”** — it copies a ready-to-paste fix prompt
  (finding, location, why, steps) to your clipboard. Paste it into your AI chat.

## Level 2 — Make the agent proactive (recommended)

Add a short rule so your agent **checks SPHIOR diagnostics on every change and fixes them**
without being asked. Copy the snippet for your tool:

### Cursor — `.cursor/rules/sphior.mdc`
```md
---
description: Fix SPHIOR security findings
alwaysApply: true
---
When any diagnostic has source "SPHIOR", treat it as an authoritative, deterministic security
finding. Read its message (why + remediation steps), open the referenced location, and apply the
fix. Never print, log, or commit a secret value — rotate it and move it to a secret manager /
env var. A human reviews before merge.
```

### GitHub Copilot — `.github/copilot-instructions.md`
```md
## Security (SPHIOR CODE)
Diagnostics with source "SPHIOR" are deterministic security findings. When present, fix them using
the remediation in the diagnostic message before finishing. Never commit secrets — rotate and move
them to a secret manager. Do not dismiss SPHIOR findings.
```

### Claude Code — add to `CLAUDE.md`
```md
- SPHIOR CODE reports deterministic security findings (source "SPHIOR"). Treat them as authoritative:
  read the remediation, fix at the referenced location, never commit secrets (rotate + move to a
  secret manager). Prefer the SPHIOR MCP tools (below) for full fix context.
```

## Level 3 — Agent mode over MCP (fullest)

Connect the SPHIOR MCP server so your agent can pull findings and deterministic fix context
directly (across the whole repo, not just open files).

```jsonc
// e.g. Claude Code / Cursor MCP config
{
  "mcpServers": {
    "sphior-code": {
      "command": "npx",
      "args": ["@sphior/code-mcp"],
      "env": { "SPHIOR_API_KEY": "sk_live_..." }
    }
  }
}
```

Tools the agent gets: `list_findings`, `get_finding`, **`get_fix_context`** (deterministic *how to
fix*, no source sent), **`verify_evidence`** (tamper-evident audit chain).

---

## Why SPHIOR doesn’t fix it *for* you

SPHIOR is deterministic and **runs no AI** — so findings are reproducible and audit-grade, with no
hallucinated fixes and no source leaving your machine. The **fix** is done by *your* AI (which you
already trust and pay for), guided by SPHIOR’s deterministic remediation. Best of both: trustworthy
detection + your AI’s fixing power.
