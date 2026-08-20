/**
 * config.ts — Environment-driven configuration with defaults.
 *
 * 環境変数から設定を読み、不正値・必須値欠落を起動時にチェックする。
 */

export interface Config {
  apiKey:  string;
  baseUrl: string;
  timeoutMs: number;
  debug: boolean;
  /** Package version (populated by build) */
  version: string;
}

const PACKAGE_VERSION = "1.0.0";

function readEnv(): Config {
  const apiKey = process.env.SPHIOR_API_KEY?.trim();
  if (!apiKey) {
    throw new Error(
      "SPHIOR_API_KEY environment variable is required.\n" +
      "Get your API key at: https://sphior.com/account/code/api-keys",
    );
  }
  if (!apiKey.startsWith("sk_")) {
    throw new Error(
      `Invalid SPHIOR_API_KEY format (expected sk_live_... or sk_test_...).\n` +
      `Get your API key at: https://sphior.com/account/code/api-keys`,
    );
  }

  const baseUrl = (process.env.SPHIOR_API_BASE?.trim() || "https://sphior.com/api/v1").replace(/\/+$/, "");
  const timeoutMs = Number(process.env.SPHIOR_TIMEOUT ?? "30000");
  const debug = ["1", "true", "yes", "on"].includes((process.env.SPHIOR_DEBUG ?? "").toLowerCase());

  if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300_000) {
    throw new Error(`SPHIOR_TIMEOUT must be between 1000 and 300000 ms (got: ${timeoutMs}).`);
  }

  return {
    apiKey,
    baseUrl,
    timeoutMs,
    debug,
    version: PACKAGE_VERSION,
  };
}

// 起動時に 1 度だけ読み込んで凍結
export const CONFIG: Config = Object.freeze(readEnv());
