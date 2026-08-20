/**
 * orchestrator.ts — マルチエンジン統合の単一点（PLAN §4.2 / P0-2）
 *
 * 複数エンジン（自前 SAST/SCA + 採用 OSS: Trivy/ZAP/Nuclei…）の CanonicalFinding[] を
 *   union → 正規化 → fingerprint dedup → クロスエンジン一致で確度昇格
 * に集約する。DAST 側の決定論（derive-disposition / confidence-model）と同じ思想を
 * SAST/SCA/IaC にも横展開する土台。
 *
 * 純関数・I/O なし・決定論（同入力→同出力）。証跡の再現性の前提（PLAN §4.2）。
 * over-claim しないため確度は既存 3 値（confirmed/likely/needs_review）のみで昇格させる。
 */

import type { CanonicalFinding, Confidence, FindingEngine, Severity } from "./types";

const CONF_RANK: Record<Confidence, number> = { needs_review: 0, likely: 1, confirmed: 2 };
const CONF_BY_RANK: Confidence[] = ["needs_review", "likely", "confirmed"];
const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** 高い方の確度を返す。 */
function maxConfidence(a: Confidence, b: Confidence): Confidence {
  return CONF_BY_RANK[Math.max(CONF_RANK[a], CONF_RANK[b])];
}
/** 高い方の重大度を返す。 */
function maxSeverity(a: Severity, b: Severity): Severity {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}

/** proof は confirmed を最優先（refuted/inconclusive より確定的）。 */
function betterProof(a: CanonicalFinding["proof"], b: CanonicalFinding["proof"]): CanonicalFinding["proof"] {
  if (!a) return b;
  if (!b) return a;
  if (a.verdict === "confirmed") return a;
  if (b.verdict === "confirmed") return b;
  return a; // 決定論のため先勝ち
}

/** クロスエンジン相関の粗いキー（CWE 無ければ rule_id）。confidence-model の CWE+URI 相関の一般化。 */
function coarseKey(f: CanonicalFinding): string {
  return `${f.cwe ?? f.rule_id}:${f.location.path}:${f.location.start_line}`;
}

function sortedEngines(set: Set<FindingEngine>): FindingEngine[] {
  return [...set].sort();
}

/** 決定論ソート: path → line → col → rule_id → engine。 */
function sortFindings(a: CanonicalFinding, b: CanonicalFinding): number {
  if (a.location.path !== b.location.path) return a.location.path < b.location.path ? -1 : 1;
  if (a.location.start_line !== b.location.start_line) return a.location.start_line - b.location.start_line;
  if (a.location.start_col !== b.location.start_col) return a.location.start_col - b.location.start_col;
  if (a.rule_id !== b.rule_id) return a.rule_id < b.rule_id ? -1 : 1;
  return (a.engine ?? "") < (b.engine ?? "") ? -1 : (a.engine ?? "") > (b.engine ?? "") ? 1 : 0;
}

/**
 * マルチエンジン統合。
 * @param inputs 各エンジンの findings（`engine` は set 済みが望ましい。未 set は既定 tag で補える）
 * @param opts.defaultEngine `engine` 未設定の finding に付与する既定
 */
export function orchestrateFindings(
  inputs: CanonicalFinding[],
  opts: { defaultEngine?: FindingEngine } = {},
): CanonicalFinding[] {
  // 0) engine を確定（未設定は defaultEngine）。
  const tagged = inputs.map((f) =>
    f.engine || !opts.defaultEngine ? f : ({ ...f, engine: opts.defaultEngine } as CanonicalFinding),
  );

  // 1) 完全一致 dedup（同一 fingerprint）。engines を union し、確度/重大度/proof を統合。
  const byFp = new Map<string, CanonicalFinding>();
  for (const f of [...tagged].sort(sortFindings)) {
    const cur = byFp.get(f.fingerprint);
    if (!cur) {
      const engines = new Set<FindingEngine>();
      if (f.engine) engines.add(f.engine);
      for (const e of f.engines ?? []) engines.add(e);
      byFp.set(f.fingerprint, { ...f, engines: engines.size ? sortedEngines(engines) : undefined });
      continue;
    }
    const engines = new Set<FindingEngine>(cur.engines ?? []);
    if (cur.engine) engines.add(cur.engine);
    if (f.engine) engines.add(f.engine);
    for (const e of f.engines ?? []) engines.add(e);
    byFp.set(f.fingerprint, {
      ...cur,
      severity: maxSeverity(cur.severity, f.severity),
      confidence: maxConfidence(cur.confidence, f.confidence),
      proof: betterProof(cur.proof, f.proof),
      engines: sortedEngines(engines),
    });
  }

  const deduped = [...byFp.values()];

  // 2) クロスエンジン相関（粗キー cwe+path+line で ≥2 エンジン一致 → confirmed 昇格）。
  //    行を統合はせず、確度と engines を注釈する（confidence-model 準拠）。
  const groupEngines = new Map<string, Set<FindingEngine>>();
  for (const f of deduped) {
    const key = coarseKey(f);
    let set = groupEngines.get(key);
    if (!set) { set = new Set<FindingEngine>(); groupEngines.set(key, set); }
    if (f.engine) set.add(f.engine);
    for (const e of f.engines ?? []) set.add(e);
  }

  const out = deduped.map((f) => {
    const set = groupEngines.get(coarseKey(f));
    if (!set || set.size < 2) return f;
    // 2 エンジン以上が同一 CWE・同一箇所を独立検出 → 実在確度↑（confirmed）。
    return {
      ...f,
      confidence: maxConfidence(f.confidence, "confirmed"),
      engines: sortedEngines(set),
    } as CanonicalFinding;
  });

  return out.sort(sortFindings);
}
