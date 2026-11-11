# Changelog

All notable changes to the **SPHIOR CODE** VS Code extension are documented here.

## [0.1.5] — 2026-11-12

- New icon: the SPHIOR ring on black, matching the brand. No functional changes.

## [0.1.4] — 2026-11-12

- Marketplace description corrected. It said the extension produces tamper-evident
  audit evidence; it does not — the extension finds problems locally, and evidence
  records are kept by the hosted service.
- The "Fix with your AI" prompt for an exposed secret no longer suggests rewriting
  git history; it says rotation is what makes the credential safe.
- No change to detection: same rule set (`2026.10.23-24`) as 0.1.3, now built from
  `@sphior/scan` 0.1.8.

## [0.1.3] — 2026-11-12

- Ships the current rule set, `2026.10.23-24`, replacing `2026.07.12-22`. Editor
  findings now match `@sphior/scan` 0.1.7 on the command line.
- New since 0.1.2, among others:
  - Weak ciphers in JavaScript/TypeScript (DES/3DES, RC2/RC4, Blowfish, IDEA, ECB).
  - Path traversal through `fs` functions imported by name, such as
    `import { readFileSync } from "node:fs"`.
  - XSS through `res.send` and `URLSearchParams` flows.
  - Inline acceptance with `// sphior-ignore` and `// sphior-ignore-next-line`.
  - Fewer false positives on private-key headers.

## [0.1.2] — 2026-10-16

- The extension pointed at a private repository, so the "Repository" link on the
  marketplace page was a 404 for everyone. It now points at the public source,
  github.com/Toraastrta/sphior-code.
- Rebuilt against the current language server. Detection is unchanged — the rule
  set is the same `2026.07.12-22` that 0.1.1 shipped.

## [0.1.1] — 2026-09-04

- Updated the extension icon to the SPHIOR brand mark. No functional changes —
  detection, the bundled language server and the Quick Fix action are unchanged.

## [0.1.0] — 2026-07-12

Initial release.

- Deterministic, local detection of hard-coded **secrets** (provider signatures + entropy,
  masked previews only) and insecure **code patterns mapped to CWE** (eval, command injection,
  XSS sinks, disabled TLS verification, weak crypto, unsafe deserialization, …).
- Powered by a bundled language server (`@sphior/scan`) — **no AI, no source upload**; your code
  never leaves your machine.
- **AI-ready diagnostics.** Each finding carries the deterministic *why* + remediation steps + a
  CWE link, so your existing AI assistant (Copilot / Cursor / Claude) can fix it accurately from
  the diagnostic alone.
- **Quick Fix → “Fix with your AI.”** A lightbulb action prepares a ready-to-paste fix prompt
  (finding, location, why, steps) and copies it to your clipboard for your AI assistant.
- Languages: JavaScript, TypeScript, JSX/TSX, Python, Go, PHP, Ruby, Java, C#, Rust,
  Kotlin, C, C++, Scala, Swift.
- `sphior.enable` setting to toggle scanning.
