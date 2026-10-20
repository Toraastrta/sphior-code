/**
 * config.ts — 環境変数から設定を読み、起動時に検証する。
 */

export interface Config {
  /** 未設定なら null。**起動は止めない** — 理由は readEnv のコメント。 */
  token: string | null;
  endpoint: string;
  timeoutMs: number;
  debug: boolean;
  version: string;
}

const PACKAGE_VERSION = "0.2.1";

function readEnv(): Config {
  // トークンが無くても**起動は通す**。ここで throw すると MCP クライアントには
  // 「サーバー起動失敗」としか映らず、Node のスタックトレースに案内が埋もれて
  // 利用者に届かない。マーケットプレイス経由で入れた人は全員まず鍵なしで触るので、
  // そこがそのまま離脱点になる。記録は受け付けない（アカウント必須は崩さない）が、
  // ツールを呼んだ時点で「どこで鍵を作るか」を返す（tools/index.ts の requiresToken）。
  const token = process.env.SPHIOR_AIGOV_TOKEN?.trim() || null;

  const endpoint = (process.env.SPHIOR_AIGOV_ENDPOINT?.trim() || "https://sphior.com/api/ai-governance/ingest").replace(/\/+$/, "");
  const timeoutMs = Number(process.env.SPHIOR_TIMEOUT ?? "30000");
  const debug = ["1", "true", "yes", "on"].includes((process.env.SPHIOR_DEBUG ?? "").toLowerCase());

  if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300_000) {
    throw new Error(`SPHIOR_TIMEOUT must be between 1000 and 300000 ms (got: ${timeoutMs}).`);
  }

  return { token, endpoint, timeoutMs, debug, version: PACKAGE_VERSION };
}

export const CONFIG: Config = Object.freeze(readEnv());
