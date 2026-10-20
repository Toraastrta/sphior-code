/**
 * detect.ts — 決定論的シークレット検出（設計 §4.1 SAST-secrets / P1-2）
 *
 * 生値は決して保存しない：snippet_hash（秘密の SHA-256）＋ マスク済みプレビュー
 * のみを保持する（設計 §6）。出力は (path,line,col,rule) で安定ソート＝決定論。
 * fingerprint は「rule + path + 秘密のハッシュ」で行ズレに強い（delta 追跡の鍵）。
 */

import type { CanonicalFinding } from "../types";
import { SCHEMA_VERSION } from "../types";
import { sha256, canonicalHash } from "../canonical";
import { looksHighEntropy, looksLikePlaceholder } from "./entropy";
import { SECRET_RULES, GENERIC_ASSIGNMENT, PLACEHOLDER_SECRETS, type SecretRule } from "./rules";

export interface DetectOptions {
  /** 除外する fingerprint（allowlist）。 */
  allowFingerprints?: Set<string>;
  /** 除外するパス（テストフィクスチャ等）。 */
  ignorePaths?: RegExp[];
}

/** 秘密のマスク済みプレビュー（先頭3・末尾2、中間は伏せる）。 */
export function maskSecret(secret: string): string {
  if (secret.length <= 6) return "•".repeat(secret.length);
  return `${secret.slice(0, 3)}…${secret.slice(-2)}`;
}

// 行頭からのオフセット表を作り、絶対 index → (line,col) に変換する。
function lineIndex(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return starts;
}
function toPos(starts: number[], index: number): { line: number; col: number } {
  // 二分探索
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, col: index - starts[lo] + 1 };
}

function build(
  path: string,
  rule: Pick<SecretRule, "id" | "provider" | "title" | "severity" | "references">,
  secret: string,
  absStart: number,
  starts: number[],
  needsReview: boolean,
): CanonicalFinding {
  const snippet_hash = sha256(secret);
  const start = toPos(starts, absStart);
  const end = toPos(starts, absStart + secret.length);
  // fingerprint: 秘密のハッシュを locator にする → 行が動いても同一
  const fingerprint = canonicalHash({ rule_id: rule.id, path, locator: snippet_hash });
  return {
    schema_version: SCHEMA_VERSION,
    kind: "sast_secret",
    rule_id: rule.id,
    cwe: "CWE-798",
    owasp: "A07:2021",
    severity: rule.severity,
    confidence: needsReview ? "needs_review" : "confirmed",
    title: rule.title,
    message: `${rule.provider} secret detected in source. Rotate it and move to a secrets manager / environment variable.`,
    location: { path, start_line: start.line, start_col: start.col, end_line: end.line, end_col: end.col },
    snippet_hash,
    masked: maskSecret(secret),
    provider: rule.provider,
    remediation:
      "Revoke/rotate the exposed credential immediately, remove it from source (and Git history), and load it from a secrets manager or environment variable at runtime.",
    references: rule.references,
    fingerprint,
  };
}

/** 単一ファイル本文からシークレットを決定論的に検出する。 */
export function detectSecrets(path: string, text: string, opts: DetectOptions = {}): CanonicalFinding[] {
  if (opts.ignorePaths?.some((re) => re.test(path))) return [];
  const starts = lineIndex(text);
  const out: CanonicalFinding[] = [];
  const seen = new Set<string>(); // fingerprint 重複抑制

  const push = (f: CanonicalFinding) => {
    if (opts.allowFingerprints?.has(f.fingerprint)) return;
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    out.push(f);
  };

  // 1) プロバイダ署名ルール（高信頼）
  for (const rule of SECRET_RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const g = rule.group ?? 0;
      const secret = m[g];
      if (!secret) continue;
      if (PLACEHOLDER_SECRETS.has(secret) || looksLikePlaceholder(secret)) continue;
      const absStart = m.index + m[0].indexOf(secret);
      push(build(path, rule, secret, absStart, starts, false));
      if (re.lastIndex === m.index) re.lastIndex++; // ゼロ幅ガード
    }
  }

  // 2) 汎用高エントロピー割当（needs_review、エントロピーで確定）
  {
    const re = new RegExp(GENERIC_ASSIGNMENT.pattern.source, "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const secret = m[1];
      if (!secret || PLACEHOLDER_SECRETS.has(secret) || looksLikePlaceholder(secret)) continue;
      if (!looksHighEntropy(secret)) continue;
      const absStart = m.index + m[0].lastIndexOf(secret);
      push(build(path, GENERIC_ASSIGNMENT, secret, absStart, starts, true));
      if (re.lastIndex === m.index) re.lastIndex++;
    }
  }

  // 決定論ソート
  out.sort((a, b) => {
    if (a.location.path !== b.location.path) return a.location.path < b.location.path ? -1 : 1;
    if (a.location.start_line !== b.location.start_line) return a.location.start_line - b.location.start_line;
    if (a.location.start_col !== b.location.start_col) return a.location.start_col - b.location.start_col;
    return a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0;
  });
  return out;
}

/** 複数ファイルをまとめて検出（path 昇順・決定論）。 */
export function detectSecretsInFiles(
  files: Array<{ path: string; text: string }>,
  opts: DetectOptions = {},
): CanonicalFinding[] {
  const all: CanonicalFinding[] = [];
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    all.push(...detectSecrets(f.path, f.text, opts));
  }
  return all;
}
