/**
 * adapt.ts — 既存 SCA(OSV) 出力 → CanonicalFinding（設計 §4.1 SCA / P1-5,6）
 *
 * 既存 `src/lib/sca/scan-dependencies.ts`（OSV 照合）の findings を、エンジンの
 * 正規化 finding に変換する。SCA は source を送らず package 座標のみで成立。
 * fingerprint は version 非依存（name + advisory）→ 修正で resolved 判定が効く。
 */

import type { CanonicalFinding, Severity } from "../types";
import { SCHEMA_VERSION } from "../types";
import { sha256, canonicalHash } from "../canonical";

/** 既存 ScaFinding の必要サブセット（純エンジン化のため構造的に受ける）。 */
export interface ScaInput {
  ecosystem: string;
  package_name: string;
  package_version: string;
  vuln_id: string; // GHSA-… / CVE-…
  severity: Severity;
  cwe?: string | null;
  owasp?: string | null;
  title?: string;
  message?: string;
  file_path?: string; // manifest/lockfile
  line_start?: number;
  fixed_version?: string | null;
}

function advisoryUrl(vulnId: string): string | undefined {
  if (vulnId.startsWith("GHSA-")) return `https://github.com/advisories/${vulnId}`;
  if (vulnId.startsWith("CVE-")) return `https://osv.dev/vulnerability/${vulnId}`;
  return `https://osv.dev/vulnerability/${vulnId}`;
}

export function scaToCanonical(input: ScaInput[]): CanonicalFinding[] {
  const seen = new Set<string>();
  const out: CanonicalFinding[] = [];

  for (const s of input) {
    const path = s.file_path || `${s.ecosystem}:manifest`;
    const coord = `${s.ecosystem}:${s.package_name}`;
    const locator = `${coord}:${s.vuln_id}`; // version 非依存
    const fingerprint = canonicalHash({ rule_id: s.vuln_id, path, locator });
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);

    const fix = s.fixed_version ? ` Upgrade ${s.package_name} to ${s.fixed_version}+.` : "";
    out.push({
      schema_version: SCHEMA_VERSION,
      kind: "sca",
      rule_id: s.vuln_id,
      cwe: s.cwe ?? undefined,
      owasp: s.owasp ?? undefined,
      severity: s.severity,
      confidence: "confirmed", // advisory 照合は決定論
      title: s.title || `${s.package_name}@${s.package_version}: ${s.vuln_id}`,
      message:
        (s.message || `Known vulnerability ${s.vuln_id} in ${s.package_name}@${s.package_version} (${s.ecosystem}).`) + fix,
      location: { path, start_line: s.line_start || 1, start_col: 1, end_line: s.line_start || 1, end_col: 1 },
      snippet_hash: sha256(`${coord}@${s.package_version}:${s.vuln_id}`),
      provider: s.ecosystem,
      remediation: s.fixed_version
        ? `Upgrade ${s.package_name} to ${s.fixed_version} or later.`
        : `Update ${s.package_name} to a non-vulnerable version, or apply the advisory's mitigation.`,
      references: [advisoryUrl(s.vuln_id)].filter((x): x is string => Boolean(x)),
      fingerprint,
    });
  }

  out.sort((a, b) => {
    if (a.location.path !== b.location.path) return a.location.path < b.location.path ? -1 : 1;
    return a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0;
  });
  return out;
}
