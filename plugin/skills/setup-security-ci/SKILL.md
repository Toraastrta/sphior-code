---
name: setup-security-ci
description: Add SPHIOR CODE security scanning to a project's CI — fail the build on serious findings and publish SARIF to GitHub code scanning. Use when the user asks to "add security scanning to CI", "scan every pull request", "block merges with secrets or vulnerabilities", "set up SAST in GitHub Actions / GitLab CI", or wants findings in the GitHub Security tab.
---

# Set up SPHIOR CODE in CI

The goal is a CI step that runs the same deterministic scan on every push and pull request,
fails when something serious appears, and leaves a report people can read. You write the CI
configuration; the scanner itself needs no account, no key and no network access beyond
installing the package.

## Step 1 — Learn the project

- Find the CI system: `.github/workflows/` (GitHub Actions), `.gitlab-ci.yml`,
  `.circleci/config.yml`, `azure-pipelines.yml`, `Jenkinsfile`, `bitbucket-pipelines.yml`.
  If there is none, ask the user which one they use. Default to GitHub Actions only if the
  repository is on GitHub.
- Find the default branch: `git symbolic-ref --short refs/remotes/origin/HEAD` (strip
  `origin/`). With no remote, use the current branch and confirm it with the user.
- On GitHub, check visibility if you can (`gh repo view --json visibility`). Uploading SARIF to
  code scanning works on public repositories; on private ones it needs GitHub Advanced Security.
  If you cannot tell, ask.

## Step 2 — Measure the current state before choosing a threshold

Run the scan locally first, from the repository root (Node.js 18+), writing outside the
repository:

```bash
OUT=$(mktemp -d)
npx -y @sphior/scan run . --json "$OUT/baseline.json"
```

Read the summary line (counts by severity, files scanned, engine and ruleset versions). Then
choose the threshold — with the user when they are available; otherwise follow this table and
say which row you used:

| Current state | `--fail-on` |
|---|---|
| No critical or high findings | `high` |
| A few critical or high findings | Fix them first (**fix-security-findings**), then `high` |
| Many existing findings | `critical` now, tighten to `high` once the backlog is fixed |

Never add `.sphiorignore` entries or ignore comments just to make the first CI run pass. Real
findings get fixed; findings that are genuinely not a problem go through
**triage-security-findings**, which records a reason.

## Step 3 — Pin the version

Look up the current version and pin it, so a ruleset update never changes CI results without a
commit:

```bash
npm view @sphior/scan version        # add --offline to read it from the local cache
```

Use **0.1.8 or later**: from 0.1.8 a mistyped option or `--fail-on` value stops with exit `2`
instead of being ignored. Write it as `npx -y @sphior/scan@<version>`, and tell the user that
updating the scanner is then a deliberate one-line change.

## Step 4 — Write the CI step

Copy the option exactly as `--fail-on high`.

### GitHub Actions

Create `.github/workflows/sphior-code.yml` (or add the job to an existing workflow):

```yaml
name: SPHIOR CODE
on:
  push:
    branches: [main]        # the real default branch
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only for the upload step
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Scan
        run: npx -y @sphior/scan@<version> run . --sarif sphior.sarif --fail-on high
      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sphior.sarif
```

- **Public repository, or Advanced Security enabled:** keep the upload step. Findings appear in
  the Security tab and as annotations on pull requests, and alerts are tracked across commits.
- **Private repository without Advanced Security:** the upload fails with 403. Replace it with
  an artifact so the report is still downloadable, and drop `security-events: write`:

```yaml
      - name: Keep the report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sphior-sarif
          path: sphior.sarif
```

### GitLab CI

```yaml
sphior-code:
  image: node:20
  script:
    - npx -y @sphior/scan@<version> run . --json sphior.json --sarif sphior.sarif --fail-on high
  artifacts:
    when: always
    paths: [sphior.json, sphior.sarif]
```

### Any other CI

Run the same command on a Node.js 18+ image and archive the SARIF or JSON. The exit code is
the contract:

| Code | Meaning |
|---|---|
| `0` | Nothing at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` — fail the build |
| `2` | Nothing was scanned: missing directory, or (0.1.8+) an unknown option or invalid value — fail the build |

A directory with no scannable files exits `0` with a warning, so make sure the step runs from
the repository root.

## Step 5 — Verify before handing over

1. **Prove the gate can fail.** A clean repository exits `0` whether the gate works or not. Run
   the exact CI command against a copy that still contains a known finding — for example a
   commit from before the fixes (`git archive <commit> | tar -x -C "$(mktemp -d)"`), or a
   temporary directory holding one file with `eval(userInput)` — and confirm exit `1`.
2. Run the exact command on the current tree and confirm the exit code you expect. Write the
   SARIF to a temporary directory when you do this locally; a `sphior.sarif` left in the
   repository is read by the next local scan and is easy to commit by mistake.
3. Validate the YAML (syntax, indentation, the real default branch name).
4. If the repository has generated or vendored code that should not be scanned, propose
   `.sphiorignore` path entries **without a rule id** (that means "do not read these files"),
   and show them to the user. Build output, `node_modules`, `vendor` and similar are already
   skipped.
5. Tell the user what will now happen on a pull request, which threshold you chose and why, and
   that accepted findings are kept out of SARIF on purpose (GitHub would otherwise show them as
   open alerts) — `--suppressed accepted.json` keeps that record if they want it archived.

## Rules

- Do not put secrets, tokens or API keys into the workflow. The scanner needs none.
- Do not weaken an existing security job to make room for this one.
- Do not claim the CI step makes the application secure or compliant. It checks source code
  for known patterns, secrets and data flows within a file; it does not check dependencies or
  the running application.
