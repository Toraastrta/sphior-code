---
name: triage-security-findings
description: Review SPHIOR CODE findings one by one and decide which are real, which are test fixtures or examples, and which are false positives — fixing the real ones and recording each accepted one with a written reason in .sphiorignore or an inline comment. Use when the user says "there are too many findings", "these are false positives", "this is test data", "clean up the scan results", "suppress this", or before turning on a CI gate on an existing codebase.
---

# Triage SPHIOR CODE findings

Triage means deciding, finding by finding, what each one is — and leaving a record a reviewer
or auditor can read later. It is **not** a way to make the number go down. A finding is only
accepted when you can write down, in one sentence, why it is not a risk in this code.

## Step 1 — Get the full list, including what is already accepted

Use the command line for triage (Node.js 18+). Write outside the repository:

```bash
OUT=$(mktemp -d)
npx -y @sphior/scan run . --json "$OUT/findings.json" --suppressed "$OUT/accepted.json"
```

Use the same scanner version as the project's CI if it pins one. Keep the summary line from
standard error; it shows how many files were scanned and how many were excluded.

- `findings.json` — open findings. Each has `rule_id`, `severity`, `confidence`, `location`
  and a stable `fingerprint`.
- `accepted.json` — findings already accepted, each with `suppression.justification` (absent
  when nobody wrote a reason) and `suppression.source` (where it was recorded). Read it so you do
  not duplicate entries.

The MCP tool `get_fix_context` is built for fixing: it has no accepted list, and its
`agent_instructions` tell a fixer not to re-classify findings. That instruction is for the fix
skill; in triage, classifying is the job.

## Step 2 — Read each finding in its real context

Open the file at the reported line and read enough code to understand the data flow. Put the
finding into exactly one bucket:

| Bucket | What it looks like | What to do |
|---|---|---|
| **Real** | Reachable code with untrusted input, a working credential, a weak algorithm used for security | **Fix it** — hand it to **fix-security-findings**. Never accept. |
| **Test data / example** | A fixture, test vector, documentation example or deliberately vulnerable sample | Accept, scoped to that path **and** that rule, with a reason |
| **False positive** | The flagged construct is safe here, and you can say why (input is a compile-time constant, value is a public identifier, the hash is not used for security) | Accept at the single line, scoped to the rule, with a reason |
| **Not our code** | Generated, vendored or third-party code that is not edited by hand | Exclude the path (no rule id) — see the caution below |

How to weigh it:

- `confidence: confirmed` means the construct itself is the problem. These are rarely false
  positives — the bar for accepting one is high.
- `confidence: needs_review` (for example the generic high-entropy secret rule) is where most
  false positives are.
- **A secret that looks real is never "test data"**, even inside a test folder. Live prefixes
  such as `sk_live_`, `AKIA`, `ghp_`, `xoxb-`, or a PEM private key with a body, are treated as
  exposed: tell the user it must be rotated, then move it out of source.
- **Generated code with a real vulnerability is both "Real" and "Not our code".** Excluding the
  path hides it from every later scan. Before excluding, list its findings in your report and tell
  the user the fix belongs in the generator or its input, not in the generated file.

## Step 3 — Record the decision in the narrowest form

**One line in ordinary code** → an inline comment with the rule id and a reason. Works with any
line comment (`//`, `#`, `--`, `;`):

```python
digest = hashlib.md5(data).hexdigest()  # sphior-ignore pattern.py.weak_hash: cache key, not a security use
```

```js
// sphior-ignore-next-line secret.generic.high_entropy_assignment: public analytics key, shipped to browsers by design
const PUBLIC_ANALYTICS_TOKEN = "3f9a6c0e1b2d4e5f8a7b6c5d4e3f2a1b";
```

**Test data, fixtures and examples** (even a single line) → `.sphiorignore` at the scan root, so
the test file stays untouched. One entry per line: `<glob> [rule_id] [# reason]`

```gitignore
# accepted: scanned, then recorded with a reason
test/fixtures/keys.js   secret.generic.high_entropy_assignment   # fake token used by unit tests
docs/examples/**        pattern.js.eval                          # intentionally insecure documentation samples

# excluded: not read at all (no rule id)
src/generated/**        # generated from openapi.yaml; findings reported to the owner on <date>
```

Rules for writing entries:

- **Always give a rule id** when accepting. A path without a rule id means "do not read this
  file at all" — use that only for generated or vendored code.
- **Always give a reason.** The CLI reports accepted findings without one; an auditor cannot
  read an empty reason.
- **Narrowest scope wins.** One rule over a family (`secret.*` only when several secret rules
  fire on the same fixture), one file over a directory, one directory over the repository. Never
  pair `**` with a broad rule.
- Do not touch existing entries written by someone else unless the user asks.

## Step 4 — Prove nothing else changed

Run the Step 1 command again and compare by **`fingerprint`** (it stays the same when lines
move):

- Every finding you accepted is now in `accepted.json`, with your reason.
- Findings under paths you excluded are gone from both lists — expected. The "files excluded"
  count in the summary line should have risen by the number of files you excluded.
- **No other finding disappeared.** If one did, your glob or rule pattern is too broad —
  narrow it.
- Real findings you handed to **fix-security-findings** are still open until that skill has run;
  check them again after it has.

## Step 5 — Report for human review

Give the user a short table:

| File:line | Rule | Decision | Reason |
|---|---|---|---|

followed by the counts (fixed / accepted / excluded / still open), the findings inside excluded
paths, and anything that needs their action, such as rotating a credential. Say clearly that the
accepted entries are your judgement and should be reviewed before merge.
