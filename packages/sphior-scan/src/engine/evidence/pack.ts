/**
 * pack.ts — evidence pack の署名マニフェスト & 独立検証（設計 §4.5）
 *
 * evidence pack（findings.csv / records.json / chain / …）の各ファイルに対する
 * per-file SHA-256 と全体 manifest_hash を生成する。監査人はインスタンスに
 * アクセスせず、手元のファイルとこの署名だけで改ざんを検証できる。
 */

import { canonicalHash, sha256 } from "../canonical";

export interface PackEntry {
  name: string;
  bytes: Buffer | string;
}

export interface PackManifest {
  algorithm: "SHA-256";
  files: Array<{ name: string; sha256: string }>;
  /** files 配列（name 昇順）の canonical ハッシュ。 */
  manifest_hash: string;
}

/** ファイル群から署名マニフェストを決定論的に生成。 */
export function buildPackManifest(entries: PackEntry[]): PackManifest {
  const files = [...entries]
    .map((e) => ({ name: e.name, sha256: sha256(typeof e.bytes === "string" ? e.bytes : e.bytes) }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { algorithm: "SHA-256", files, manifest_hash: canonicalHash(files) };
}

export interface PackVerifyResult {
  ok: boolean;
  /** 改ざん/欠落/余剰のあったファイル名。 */
  mismatches: string[];
  manifestOk: boolean;
}

/** 手元のファイル群を manifest と照合（独立検証）。 */
export function verifyPackManifest(entries: PackEntry[], manifest: PackManifest): PackVerifyResult {
  const recomputed = buildPackManifest(entries);
  const expected = new Map(manifest.files.map((f) => [f.name, f.sha256]));
  const got = new Map(recomputed.files.map((f) => [f.name, f.sha256]));
  const mismatches: string[] = [];
  for (const [name, hash] of expected) {
    if (got.get(name) !== hash) mismatches.push(name);
  }
  for (const name of got.keys()) {
    if (!expected.has(name)) mismatches.push(name); // 余剰ファイル
  }
  const manifestOk = recomputed.manifest_hash === manifest.manifest_hash;
  return { ok: mismatches.length === 0 && manifestOk, mismatches: [...new Set(mismatches)].sort(), manifestOk };
}
