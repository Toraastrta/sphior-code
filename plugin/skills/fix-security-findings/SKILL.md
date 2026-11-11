---
name: fix-security-findings
description: Find and fix security problems in the current codebase with SPHIOR CODE — hard-coded secrets, insecure patterns mapped to CWE, and taint flows (untrusted input reaching a shell, SQL, eval, HTML, file-path or URL sink). Use when the user says things like "scan this project", "check this for vulnerabilities", "fix the security issues", "is there a SQL injection here", "any hard-coded keys?", or asks for a security review of a file or directory.
---

# Fix security findings with SPHIOR CODE

SPHIOR CODE finds the problems deterministically; **you** write the fix. The scanner never
generates code and never uploads source. It returns the location and the remediation, and you
read the real code from the workspace you already have.

## Step 1 — Get the findings

Use the first option that is available.

**A. The `sphior-code` MCP server** (installed with the SPHIOR CODE plugin, or by the user).
Call `get_fix_context`.

- No arguments → scans the directory this session is working in.
- `path` → scan one directory instead. On a large repository, start narrow.
- `severity` → `critical` / `high` / `medium` / `low`.

**B. The command line** (Node.js 18+). Write the fix context to a temporary directory, outside
the repository, and read it:

```bash
OUT=$(mktemp -d)
npx -y @sphior/scan run <dir> --fix-context "$OUT/fix.json"
```

If the project's CI pins a version (`@sphior/scan@x.y.z`), use the same one so your result
matches CI. The file is a JSON array with one entry per place to fix, most severe first. Exit
code `2` means nothing was scanned (missing directory or a bad option) — never report that as a
clean result.

**C. Neither can run here** (no terminal, no network). Ask the user to run the command in B on
their machine and attach the file, or the output of `--json`. Work from that file.

All three need no account and send no source code anywhere.

## Step 2 — Read what came back

Each entry is one **place to fix**, not one rule hit:

| Field | Use it for |
|---|---|
| `location` | `path`, `start_line`, `end_line`. **Read the real code yourself** — it is not in the payload. |
| `rule_id` | The rule. Ids starting with `taint.` are data-flow findings: untrusted input reaches this line from somewhere else in the file. |
| `why`, `summary` | Why it matters. Fix the cause, not the symptom. |
| `remediation_steps` | The concrete steps. Follow them, with the exceptions in Step 3. |
| `also` | **Other findings on the same line** (`rule_id`, `title`, `severity`, `cwe`). One edit must satisfy all of them; their steps are already merged into `remediation_steps`. |
| `masked_preview` | A masked secret (`sk_…tY`). Never print, log, or commit the real value. |
| `severity`, `confidence` | Work from `critical` down. `confirmed` means the construct itself is the problem. |
| `agent_instructions` | Guardrails for you: do not dismiss the finding, never expose a secret, a human reviews the change. |
| `cwe`, `owasp`, `references` | Background when you need it. |

## Step 3 — The loop

1. Get the findings (Step 1).
2. For each entry, open `location.path` at `location.start_line` and read the surrounding code.
   For a `taint.` finding, find where the input comes from before editing.
3. Apply `remediation_steps`. If `also` is non-empty, your single edit must clear every finding
   listed there — not only the first.
   - **Never rewrite git history** (`git filter-repo`, BFG, force-push), even if a step mentions
     it. Tell the user instead; it is their decision.
   - If a step cannot be done here (for example a regression test that needs packages that are
     not installed), say so in your report rather than skipping it silently.
4. **Scan again to confirm the findings are gone.**
5. Run the project's own tests, and check that they actually load the files you changed. If no
   test exercises the changed code, say **"the change is untested"** — do not report "tests pass"
   as if it covered the fix.

Steps 4 and 5 are both required. Passing one without the other means nothing.

## Fixing well, not just quietly

- **Hard-coded secret** — remove it from source and read it from the environment or a secret
  manager. Then tell the user, in plain words, that **the exposed value must be rotated**: it is
  in git history and should be treated as already compromised. You cannot rotate it for them.
- **Command injection** — use `execFile` / `spawn` / `subprocess.run([...])` with an argument
  array. Never build a shell string from input. Put `--` before user-controlled arguments.
- **SQL / NoSQL injection** — parameterised queries with bound values, in the placeholder style
  of the database client the project uses. Never concatenate.
- **`eval` / dynamic code** — replace with data parsing or an explicit, non-executing lookup.
  Do not "sanitise" the input and keep `eval`.
- **XSS** — use the framework's escaping or a text API (`textContent`), not `innerHTML` or raw
  `res.send` of input.
- **Path traversal** — resolve the path, then check it stays under an allowed base directory;
  or map an identifier to a known file instead of taking a path.
- **SSRF** — allow-list the destination host and scheme; do not fetch arbitrary URLs from input.
- **Unsafe deserialization** — use a data-only format (JSON) or a safe loader
  (`yaml.safe_load`). Never `pickle` untrusted bytes.
- **Weak crypto / disabled TLS verification** — use a current algorithm (SHA-256+, AES-GCM) and
  keep certificate verification on.

Keep behaviour the same unless the fix requires a change; if it does, say what changed.

## Rules

- Never make a finding disappear without fixing it: no ignore comment, no `.sphiorignore`
  entry, no narrowing of a rule, no deleted test. If a finding is genuinely not a problem, stop
  and use the **triage-security-findings** skill, which records the reason for a human.
- Never print or commit a raw secret, including in a commit message or a log line.
- Detection is deterministic — the same code and scanner version always produce the same
  findings. If a finding looks wrong, say so to the user with your reasoning; do not silently
  skip it.
- **A human reviews before merge.** Say what you changed, what is untested, and what still needs
  their action (rotating a credential, for example).

## What the scan covers

- **14 languages**, parsed with real grammars: JavaScript, TypeScript (+ JSX/TSX), Python, Go,
  PHP, Ruby, Java, C#, Rust, Kotlin, C, C++, Scala, Swift.
- **Secrets** in every text file, including `.env*` and `*.example` — but only the current files,
  not git history.
- **Insecure patterns mapped to CWE** in all 14 languages.
- **Taint analysis** in 13 languages, followed across functions **within one file**. Flows that
  cross files, or pass through closures and callbacks, are not followed.
- **Not covered:** dependency vulnerabilities (the local scan reads source, not lockfiles) and
  anything at runtime. Do not tell the user a clean scan means the application is secure.
