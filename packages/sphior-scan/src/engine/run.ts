/**
 * run.ts — 統合スキャン（secrets + CWE パターン + SCA → findings + SARIF）
 *
 * 全 surface（CI/IDE/MCP/CLI）が呼ぶエンジンのエントリ。決定論的に
 * findings を集約し、SARIF を生成する（設計 §4.1）。
 */

import type { CanonicalFinding } from "./types";
import { ENGINE_VERSION, RULESET_VERSION } from "./version";
import { detectSecretsInFiles, type DetectOptions } from "./secrets/detect";
import { detectPatternsInFiles } from "./patterns/detect";
import { scaToCanonical, type ScaInput } from "./sca/adapt";
import { toSarif } from "./sarif";

export interface ScanFile {
  path: string;
  text: string;
}

export interface RunScanInput {
  files?: ScanFile[];
  sca?: ScaInput[];
  allowFingerprints?: Set<string>;
  ignorePaths?: RegExp[];
}

const kindOrder: Record<CanonicalFinding["kind"], number> = {
  sast_secret: 0,
  sast_pattern: 1,
  sca: 2,
  iac_misconfig: 3,
};

export interface RunScanResult {
  findings: CanonicalFinding[];
  sarif: ReturnType<typeof toSarif>;
  engine_version: string;
  ruleset_version: string;
}

export function runScan(input: RunScanInput): RunScanResult {
  const files = input.files ?? [];
  const opts: DetectOptions = { allowFingerprints: input.allowFingerprints, ignorePaths: input.ignorePaths };

  const findings: CanonicalFinding[] = [
    ...detectSecretsInFiles(files, opts),
    ...detectPatternsInFiles(files, opts),
    ...scaToCanonical(input.sca ?? []),
  ];

  // 決定論ソート: path → line → col → kind → rule_id
  findings.sort((a, b) => {
    if (a.location.path !== b.location.path) return a.location.path < b.location.path ? -1 : 1;
    if (a.location.start_line !== b.location.start_line) return a.location.start_line - b.location.start_line;
    if (a.location.start_col !== b.location.start_col) return a.location.start_col - b.location.start_col;
    if (kindOrder[a.kind] !== kindOrder[b.kind]) return kindOrder[a.kind] - kindOrder[b.kind];
    return a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0;
  });

  const sarif = toSarif(findings, { engineVersion: ENGINE_VERSION, rulesetVersion: RULESET_VERSION });
  return { findings, sarif, engine_version: ENGINE_VERSION, ruleset_version: RULESET_VERSION };
}
