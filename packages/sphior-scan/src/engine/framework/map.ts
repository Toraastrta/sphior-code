/**
 * map.ts — finding → コンプライアンス統制マッピング（North Star「framework にマップ」）
 *
 * 継続スキャン＋改ざん不可の証跡は、複数フレームワークの統制の「補助証跡」に
 * なる。finding の CWE/OWASP と、全コード走査が支える baseline 統制を対応づけ、
 * 月次レポートの framework マッピング表（P5-2）へ供給する。
 *
 * 注: これは「達成」判定ではなく監査支援用途の対応表（[[feedback-no-compliance-attestation]]）。
 */

import type { CanonicalFinding } from "../types";

export type Framework = "SOC 2" | "ISO 27001" | "OWASP" | "PCI DSS";

export interface ControlRef {
  framework: Framework;
  id: string;
  title: string;
}

const key = (c: ControlRef) => `${c.framework}::${c.id}`;

// 全コード走査（SAST+SCA）＋証跡が支える基盤統制
const BASELINE: ControlRef[] = [
  { framework: "SOC 2", id: "CC7.1", title: "Detection of vulnerabilities / monitoring" },
  { framework: "SOC 2", id: "CC8.1", title: "Change management" },
  { framework: "ISO 27001", id: "A.8.8", title: "Management of technical vulnerabilities" },
  { framework: "ISO 27001", id: "A.8.28", title: "Secure coding" },
  { framework: "PCI DSS", id: "6.3.1", title: "Identify security vulnerabilities" },
];

// CWE 固有の追加統制
const CWE_CONTROLS: Record<string, ControlRef[]> = {
  "CWE-798": [
    { framework: "SOC 2", id: "CC6.1", title: "Logical access / credential protection" },
    { framework: "ISO 27001", id: "A.8.24", title: "Use of cryptography / secrets management" },
  ],
  "CWE-327": [{ framework: "ISO 27001", id: "A.8.24", title: "Use of cryptography" }],
  "CWE-295": [{ framework: "ISO 27001", id: "A.8.20", title: "Network security (TLS)" }],
  "CWE-1321": [{ framework: "PCI DSS", id: "6.3.3", title: "Patch known vulnerabilities" }],
};

// OWASP A0x:2021 → 統制参照
const OWASP_TITLES: Record<string, string> = {
  "A01:2021": "Broken Access Control",
  "A02:2021": "Cryptographic Failures",
  "A03:2021": "Injection",
  "A05:2021": "Security Misconfiguration",
  "A06:2021": "Vulnerable and Outdated Components",
  "A07:2021": "Identification and Authentication Failures",
  "A08:2021": "Software and Data Integrity Failures",
};

/** 単一 finding が補助証跡となる統制群（重複排除・決定論ソート）。 */
export function mapFindingToControls(f: CanonicalFinding): ControlRef[] {
  const map = new Map<string, ControlRef>();
  for (const c of BASELINE) map.set(key(c), c);
  if (f.cwe && CWE_CONTROLS[f.cwe]) for (const c of CWE_CONTROLS[f.cwe]) map.set(key(c), c);
  if (f.owasp && OWASP_TITLES[f.owasp]) {
    const c: ControlRef = { framework: "OWASP", id: f.owasp, title: OWASP_TITLES[f.owasp] };
    map.set(key(c), c);
  }
  return [...map.values()].sort((a, b) =>
    a.framework !== b.framework ? (a.framework < b.framework ? -1 : 1) : a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
}

export interface ControlCoverage {
  control: ControlRef;
  finding_count: number;
}

/** findings 全体 → 統制別の裏付け件数（レポートの framework 表）。 */
export function summarizeControls(findings: CanonicalFinding[]): ControlCoverage[] {
  const counts = new Map<string, ControlCoverage>();
  for (const f of findings) {
    for (const c of mapFindingToControls(f)) {
      const k = key(c);
      const cur = counts.get(k);
      if (cur) cur.finding_count++;
      else counts.set(k, { control: c, finding_count: 1 });
    }
  }
  return [...counts.values()].sort((a, b) => {
    const ca = a.control;
    const cb = b.control;
    return ca.framework !== cb.framework
      ? ca.framework < cb.framework
        ? -1
        : 1
      : ca.id < cb.id
        ? -1
        : ca.id > cb.id
          ? 1
          : 0;
  });
}
