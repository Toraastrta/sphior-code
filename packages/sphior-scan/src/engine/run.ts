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
import { applySuppressions, type SphiorignoreConfig } from "./suppress";

export interface ScanFile {
  path: string;
  text: string;
}

export interface RunScanInput {
  files?: ScanFile[];
  sca?: ScaInput[];
  allowFingerprints?: Set<string>;
  ignorePaths?: RegExp[];
  /**
   * `.sphiorignore` のルール限定行（抑制）。パス除外は collect 側で済んでいる前提。
   * インライン抑制（`sphior-ignore` コメント）は files の本文から常に読む。
   */
  suppress?: SphiorignoreConfig;
}

const kindOrder: Record<CanonicalFinding["kind"], number> = {
  sast_secret: 0,
  sast_pattern: 1,
  sca: 2,
  iac_misconfig: 3,
};

export interface RunScanResult {
  /** 抑制されていない finding。既存の全呼び出し元（CLI/MCP/LSP/証跡）が読む正。 */
  findings: CanonicalFinding[];
  /**
   * 検出したが抑制した finding（`suppression` 付き）。
   * findings には含めない（既存の件数・ハッシュの意味を変えないため）。
   */
  suppressed: CanonicalFinding[];
  sarif: ReturnType<typeof toSarif>;
  engine_version: string;
  ruleset_version: string;
}

export function runScan(input: RunScanInput): RunScanResult {
  const files = input.files ?? [];
  const opts: DetectOptions = { allowFingerprints: input.allowFingerprints, ignorePaths: input.ignorePaths };

  const detected: CanonicalFinding[] = [
    ...detectSecretsInFiles(files, opts),
    ...detectPatternsInFiles(files, opts),
    ...scaToCanonical(input.sca ?? []),
  ];

  // 決定論ソート: path → line → col → kind → rule_id
  detected.sort((a, b) => {
    if (a.location.path !== b.location.path) return a.location.path < b.location.path ? -1 : 1;
    if (a.location.start_line !== b.location.start_line) return a.location.start_line - b.location.start_line;
    if (a.location.start_col !== b.location.start_col) return a.location.start_col - b.location.start_col;
    if (kindOrder[a.kind] !== kindOrder[b.kind]) return kindOrder[a.kind] - kindOrder[b.kind];
    return a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0;
  });

  // 抑制の仕分け（ソート後に行う → active / suppressed どちらも決定論順）
  const { active: findings, suppressed } = applySuppressions(detected, {
    config: input.suppress,
    textByPath: new Map(files.map((f) => [f.path, f.text])),
  });

  // SARIF には抑制分を載せない。GitHub Code scanning は `result.suppressions` を
  // 解釈しないため（公式の supported properties に無い）、載せると抑制したはずの
  // finding が普通の open アラートとして並ぶ逆効果になる。抑制の事実は
  // RunScanResult.suppressed（→ `--json` / 証跡）に残す。
  const sarif = toSarif(findings, { engineVersion: ENGINE_VERSION, rulesetVersion: RULESET_VERSION });
  return { findings, suppressed, sarif, engine_version: ENGINE_VERSION, ruleset_version: RULESET_VERSION };
}
