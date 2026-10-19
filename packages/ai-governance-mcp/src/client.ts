/**
 * client.ts — SPHIOR AI Governance 取込エンドポイントへの最小 POST クライアント。
 * hash_only: ペイロードは受領時にハッシュ化される。中身は保存されない。
 */

import { CONFIG } from "./config.js";

export interface IngestResult {
  ok: boolean;
  recorded?: number;
  retention?: string;
  error?: string;
}

export async function ingest(body: unknown): Promise<IngestResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CONFIG.timeoutMs);
  try {
    const res = await fetch(CONFIG.endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${CONFIG.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const json = (await res.json().catch(() => ({}))) as { recorded?: number; retention?: string; error?: string };
    if (!res.ok) {
      return { ok: false, error: `ingest failed: ${res.status} ${json.error ?? ""}`.trim() };
    }
    return { ok: true, recorded: json.recorded ?? 0, retention: json.retention ?? "hash_only" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  } finally {
    clearTimeout(timer);
  }
}
