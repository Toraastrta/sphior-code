---
name: fix-security-findings
description: Find and fix security problems in the current codebase — hard-coded secrets, insecure patterns mapped to CWE, and taint flows (untrusted input reaching a shell, SQL, or eval sink). Use when the user says things like "scan this project", "check this for vulnerabilities", "fix the security issues", "is there a SQL injection here", "any hard-coded keys?", or before shipping/releasing. Also use when they ask for a security review of a file or directory.
---

# Fix security findings with SPHIOR CODE

SPHIOR CODE finds the problems deterministically; **you** write the fix. The scanner
never generates code and never uploads source — it returns the location and the
remediation, and you read the real code from the workspace you already have.

## How to run it

Call the `get_fix_context` tool from the `sphior-code` MCP server.

- No arguments → scans the directory this session is working in.
- `path` → scan one directory instead (use this on large repos; start narrow).
- `severity` → filter to `critical` / `high` / `medium` / `low`.

It needs no account and makes no network call. If the user has set `SPHIOR_API_KEY`,
the same tool also reaches findings from repositories connected to SPHIOR.

## What comes back, and how to use it

Each entry is one **place to fix**, not one rule hit:

| field | use it for |
|---|---|
| `location` | the file and line to open. **Read the real code yourself** — it is not in the payload |
| `why` | why it matters; keep this in mind so the fix addresses the cause, not the symptom |
| `remediation_steps` | the concrete steps. Follow them |
| `also` | **other findings at the same line.** One fix must satisfy all of them |
| `masked_preview` | a masked secret (`sk_…tY`). Never print, log, or commit the real value |
| `cwe` / `references` | background when you need it |

## The loop

1. Call `get_fix_context`.
2. For each entry, open `location.path` at `location.start_line` and read the actual code.
3. Apply `remediation_steps`. If `also` is non-empty, your single edit must clear every
   finding listed there — do not fix only the first.
4. **Re-run `get_fix_context` to confirm the findings are gone.**
5. Run the project's own tests. A change that silences the scanner but breaks behaviour
   is not a fix.

Step 4 and 5 are both required. Passing one without the other means nothing.

## Fixing well, not just quietly

- **Hard-coded secret** — remove it from source and read it from the environment or a
  secret manager. Then tell the user, in plain words, that **the exposed value must be
  rotated**: it is in git history and should be treated as already compromised. You
  cannot rotate it for them.
- **Command injection** — use `execFile`/`spawn` with an argument array. Never build a
  shell string from input. Add `--` before user-controlled arguments so they cannot be
  read as options.
- **SQL injection** — parameterised queries with bound values. Never concatenate.
- **`eval` / dynamic code** — replace with data parsing or an explicit, non-executing
  substitution. Do not "sanitise" the input and keep `eval`.
- **Taint findings** — the sink is where it was reported, but the fix may belong at the
  source or in between. Follow the flow before editing.

## Rules

- Never weaken a finding to make it disappear (do not add an ignore comment, do not
  narrow a rule, do not delete a test).
- Never print or commit a raw secret, including in a commit message or a log line.
- Detection is deterministic — the same code always produces the same findings. If a
  finding looks wrong, say so to the user with your reasoning; do not silently skip it.
- **A human reviews before merge.** Say what you changed and what still needs their
  action (rotating a credential, for example).

## Scope

**14 languages** — JavaScript, TypeScript (+ JSX/TSX), Python, Go, PHP, Ruby, Java, C#,
Rust, Kotlin, C, C++, Scala, Swift — parsed with real grammars, not regex alone.

Coverage is not uniform, so do not assume a clean scan means more than it does:

- **Secrets** (provider signatures + entropy) and **insecure patterns mapped to CWE** —
  all 14 languages.
- **Taint analysis** (intra- and inter-procedural, multi-level) — **JavaScript and
  TypeScript only.** The other languages get secrets and pattern rules, not data-flow.
- **Dependency vulnerabilities (SCA)** — **not part of this local scan.** They are
  reported for repositories connected to SPHIOR, which needs `SPHIOR_API_KEY`.
