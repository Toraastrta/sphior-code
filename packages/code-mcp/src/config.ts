/**
 * config.ts — Environment-driven configuration with defaults.
 *
 * 環境変数から設定を読み、不正値・必須値欠落を起動時にチェックする。
 */

import { createRequire } from "node:module";

/**
 * 動作モード:
 *  - "local" … SPHIOR_API_KEY なし。同梱の決定論エンジンでワークスペースを走査し、
 *              get_fix_context だけをローカルで返す（アカウント不要で価値が完結する経路）。
 *  - "cloud" … API キーあり。サーバー側の finding・証跡・履歴まで使える。
 */
export type Mode = "local" | "cloud";

export interface Config {
  mode: Mode;
  /** local モードでは null。 */
  apiKey:  string | null;
  baseUrl: string;
  timeoutMs: number;
  debug: boolean;
  /** Package version (populated by build) */
  version: string;
}

// package.json を正とする。固定値にすると公開版とズレる（1.1.0 を出した時点で
// serverInfo は 1.0.0 のままだった）。dist/ も src/ も一つ上が package root。
const PACKAGE_VERSION: string = (() => {
  try {
    return createRequire(import.meta.url)("../package.json").version as string;
  } catch {
    return "0.0.0";
  }
})();

function readEnv(): Config {
  // キー未設定は異常ではなく local モード。鍵を取りに行かせずに試せることを優先する
  // （拡張は 100% ローカルで動くのに MCP だけアカウント必須、という非対称を解消する）。
  const apiKey = process.env.SPHIOR_API_KEY?.trim() || null;
  if (apiKey && !apiKey.startsWith("sk_")) {
    throw new Error(
      `Invalid SPHIOR_API_KEY format (expected sk_live_... or sk_test_...).\n` +
      `Get your API key at: https://sphior.com/app?settings=api`,
    );
  }

  const baseUrl = (process.env.SPHIOR_API_BASE?.trim() || "https://sphior.com/api/v1").replace(/\/+$/, "");
  const timeoutMs = Number(process.env.SPHIOR_TIMEOUT ?? "30000");
  const debug = ["1", "true", "yes", "on"].includes((process.env.SPHIOR_DEBUG ?? "").toLowerCase());

  if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300_000) {
    throw new Error(`SPHIOR_TIMEOUT must be between 1000 and 300000 ms (got: ${timeoutMs}).`);
  }

  return {
    mode: apiKey ? "cloud" : "local",
    apiKey,
    baseUrl,
    timeoutMs,
    debug,
    version: PACKAGE_VERSION,
  };
}

// 起動時に 1 度だけ読み込んで凍結
export const CONFIG: Config = Object.freeze(readEnv());
