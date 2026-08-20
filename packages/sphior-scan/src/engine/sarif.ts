/**
 * sarif.ts — CanonicalFinding[] → SARIF 2.1.0（設計 §4.1 / §5）
 *
 * SARIF は GitHub Code Scanning（Security タブ）・各 IDE・証跡スパインの
 * 共通相互運用フォーマット。決定論的に生成（rule/result を安定ソート）。
 * partialFingerprints に fingerprint を載せ、GitHub 側の重複排除と
 * SPHIOR の delta 追跡を一致させる。
 */

import type { CanonicalFinding, Severity } from "./types";

// severity → SARIF level
function level(sev: Severity): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}
// severity → GitHub security-severity（0-10）
function securityScore(sev: Severity): string {
  return { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" }[sev];
}

export interface SarifMeta {
  engineVersion: string;
  rulesetVersion: string;
  infoUri?: string;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: { tags: string[]; "security-severity": string };
}

export function toSarif(findings: CanonicalFinding[], meta: SarifMeta) {
  // ── rules（ユニーク・id 昇順） ──
  const ruleMap = new Map<string, SarifRule>();
  for (const f of findings) {
    if (ruleMap.has(f.rule_id)) continue;
    const tags = ["security"];
    if (f.cwe) tags.push(`external/cwe/${f.cwe.toLowerCase()}`);
    if (f.owasp) tags.push(`owasp/${f.owasp}`);
    ruleMap.set(f.rule_id, {
      id: f.rule_id,
      name: f.title,
      shortDescription: { text: f.title },
      fullDescription: { text: f.message },
      helpUri: f.references?.[0],
      properties: { tags, "security-severity": securityScore(f.severity) },
    });
  }
  const rules = [...ruleMap.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // ── results（安定ソート済みの findings をそのまま） ──
  const sorted = [...findings].sort((a, b) => {
    if (a.location.path !== b.location.path) return a.location.path < b.location.path ? -1 : 1;
    if (a.location.start_line !== b.location.start_line) return a.location.start_line - b.location.start_line;
    if (a.location.start_col !== b.location.start_col) return a.location.start_col - b.location.start_col;
    return a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0;
  });

  const results = sorted.map((f) => ({
    ruleId: f.rule_id,
    level: level(f.severity),
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.location.path },
          region: {
            startLine: f.location.start_line,
            startColumn: f.location.start_col,
            endLine: f.location.end_line,
            endColumn: f.location.end_col,
          },
        },
      },
    ],
    partialFingerprints: { sphiorFingerprint: f.fingerprint },
    properties: {
      cwe: f.cwe,
      owasp: f.owasp,
      provider: f.provider,
      confidence: f.confidence,
      snippet_hash: f.snippet_hash,
    },
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SPHIOR CODE",
            informationUri: meta.infoUri ?? "https://sphior.com",
            version: meta.engineVersion,
            semanticVersion: meta.engineVersion,
            properties: { rulesetVersion: meta.rulesetVersion },
            rules,
          },
        },
        results,
      },
    ],
  };
}
