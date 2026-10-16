# Changelog

All notable changes to the **SPHIOR CODE** VS Code extension are documented here.

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
