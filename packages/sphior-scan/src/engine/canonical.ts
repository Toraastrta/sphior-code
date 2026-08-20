/**
 * canonical.ts — 決定論シリアライズ & ハッシュ（設計 §4.1 / §5）
 *
 * 同一入力 → 同一バイト列 → 同一ハッシュ。証跡（Merkle root / chain）の
 * 再現性・改ざん検知の土台。オブジェクトキーを再帰的にソートし、undefined を
 * 除去した安定 JSON を出力する。
 */

import { createHash } from "node:crypto";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** キー再帰ソート・undefined 除去した安定表現へ正規化。 */
function stabilize(value: unknown): Json {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map(stabilize);
  if (typeof value === "object") {
    const src = value as Record<string, unknown>;
    const out: { [k: string]: Json } = {};
    for (const key of Object.keys(src).sort()) {
      if (src[key] === undefined) continue; // undefined は落とす
      out[key] = stabilize(src[key]);
    }
    return out;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical: non-finite number");
    return value;
  }
  return value as Json;
}

/** 決定論的な canonical JSON 文字列。 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(stabilize(value));
}

/** 文字列/バッファの SHA-256（hex）。 */
export function sha256(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** 任意オブジェクトの canonical ハッシュ（証跡・fingerprint 用）。 */
export function canonicalHash(value: unknown): string {
  return sha256(canonicalJson(value));
}
