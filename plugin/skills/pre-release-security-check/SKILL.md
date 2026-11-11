---
name: pre-release-security-check
description: Run a SPHIOR CODE security gate before a release, merge or deploy and give a clear ready / not-ready verdict — no exposed secrets and no open critical or high findings. Use when the user says "is this ready to ship", "check before release", "pre-merge security check", "can I deploy this", "final security pass", or is about to tag a version or open a release pull request.
---

# Pre-release security check

A short, repeatable gate. You run one deterministic scan, apply fixed criteria, and report a
verdict with the evidence behind it. The same code and scanner version always give the same
verdict.

## Step 1 — Run the scan

From the repository root (Node.js 18+), or the directory being released. If the project's CI
pins a scanner version, use the same one. Write outside the repository:

```bash
OUT=$(mktemp -d)
npx -y @sphior/scan run . --json "$OUT/open.json" --suppressed "$OUT/accepted.json"
```

Keep the summary line from standard error: it records files scanned, files excluded, accepted
findings, and the engine and ruleset versions. Those go into the report.

**Stop and report "not checked"** if:

- the exit code is `2` (missing directory or a bad option — nothing was scanned), or
- the summary says no files were scanned.

Neither is a pass.

## Step 2 — Apply the criteria

| Check | Pass when |
|---|---|
| Exposed secrets | **Zero open** findings with `kind: "sast_secret"` in `open.json`, at any severity |
| Serious findings | **Zero open** findings with severity `critical` or `high` in `open.json` |
| Accepted findings | Every entry in `accepted.json` has `suppression.justification` |
| Excluded paths | Report the "files excluded" count. List `.sphiorignore` lines without a rule id and flag any that are not generated or vendored code |
| Medium and below | Reported, not blocking — unless the user set a stricter bar |

If the project already has a CI threshold (`--fail-on` in its workflow), say whether this
result would pass it. If it has a scan step without `--fail-on`, point out that its CI never
fails on findings.

## Step 3 — Report the verdict

Start with one line: **Ready** or **Not ready**.

Then:

- Counts by severity, files scanned and excluded, engine and ruleset versions.
- **Blocking items**, each as `file:line — title (rule id, CWE)`.
- Accepted findings: how many, and any without a reason.
- Excluded paths that look like hand-written code.
- Non-blocking medium and low findings, summarised.
- **Needs action even if Ready:** any secret removed from source in this branch is still in git
  history. List it under "rotate this credential" — a clean scan of the current files does not
  make it safe.

Keep it factual. Do not soften a "not ready".

## Step 4 — If it is not ready

Offer to fix the blocking items with **fix-security-findings**, then run this check again.
For a finding the user believes is not a problem, use **triage-security-findings** so the
decision is recorded with a reason.

Never change `.sphiorignore`, add ignore comments, or raise a threshold to turn "not ready"
into "ready".

## What this check does not cover

Say this in the report, briefly:

- **Dependencies are not checked.** The scan reads source files, not lockfiles. Run the package
  manager's audit (`npm audit`, `pip-audit`, `govulncheck`, …) or a dependency scanner as well.
- Git history is not scanned; data flow is followed within a file, not across files.
- It is a source-code check, not a penetration test, and it is not a compliance verdict.
