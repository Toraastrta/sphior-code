/**
 * api-client.ts — SPHIOR CODE REST API クライアント
 *
 * 機能:
 *   - Bearer 認証
 *   - Exponential backoff retry (5xx, network, timeout)
 *   - 構造化エラー (status code + hint message)
 *   - タイムアウト保護 (AbortSignal)
 *   - User-Agent でバージョン送信
 */

import { CONFIG } from "./config.js";
import { log } from "./logger.js";

// ── Types (API response 型定義 — server 側と整合) ─────────────────────────────

export interface Finding {
  id:                     string;
  severity:               "critical" | "high" | "medium" | "low";
  rule_type:              string;
  title:                  string;
  message:                string;
  file_path:              string;
  line_start:             number;
  language:               string | null;
  cwe:                    string | null;
  cvss_base:              number | null;
  fix_hint:               string | null;
  fix_available:          boolean;
  resolved_at:            string | null;
  false_positive_marked:  boolean;
  risk_accepted:          boolean;
  repo_full_name:         string | null;
  created_at:             string;
}

export interface FindingDetail extends Finding {
  instance_key:  string;
  finding_key:   string;
  pr_number:     number | null;
  commit_sha:    string | null;
  owasp:         string | null;
  column_start:  number | null;
  last_seen:     string;
}

export interface SecuritySummary {
  total_open:       number;
  critical:         number;
  high:             number;
  medium:           number;
  low:              number;
  last_scan_at:     string | null;
  repos_monitored:  number;
}

export interface FixProposal {
  explanation:    string;
  patched_code:   string;
  test_suggestion: string | null;
  cvss_after_fix: number | null;
}

// ── Error ─────────────────────────────────────────────────────────────────────

export class SphiorApiError extends Error {
  constructor(
    public readonly status:   number,
    public readonly endpoint: string,
    message: string,
    public readonly hint?:    string,
  ) {
    super(message);
    this.name = "SphiorApiError";
  }

  /** MCP クライアント向けの人間可読フォーマット */
  toUserMessage(): string {
    const lines = [`${this.message} (status ${this.status} on ${this.endpoint})`];
    if (this.hint) lines.push(`Hint: ${this.hint}`);
    return lines.join("\n");
  }
}

// ── Retry helper ──────────────────────────────────────────────────────────────

const MAX_RETRIES   = 3;
const BACKOFF_BASE  = 500; // ms

async function withRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      // 4xx は retry しない
      if (err instanceof SphiorApiError && err.status < 500 && err.status !== 0) {
        throw err;
      }
      if (attempt === MAX_RETRIES - 1) break;
      const delay = BACKOFF_BASE * Math.pow(2, attempt); // 500ms → 1s → 2s
      log.warn(`${label} failed (attempt ${attempt + 1}/${MAX_RETRIES}), retrying in ${delay}ms`, {
        error: err instanceof Error ? err.message : String(err),
      });
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

// ── HTTP wrapper ──────────────────────────────────────────────────────────────

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?:   unknown;
  query?:  Record<string, string | number | undefined>;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? "GET";

  // query string 構築 (undefined はスキップ)
  let url = `${CONFIG.baseUrl}${path}`;
  if (opts.query) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== null) qs.set(k, String(v));
    }
    const q = qs.toString();
    if (q) url += `?${q}`;
  }

  const endpoint = `${method} ${path}`;

  return withRetry(endpoint, async () => {
    log.debug(`→ ${endpoint}`);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CONFIG.timeoutMs);

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: {
          "Authorization": `Bearer ${CONFIG.apiKey}`,
          "Content-Type":  "application/json",
          "User-Agent":    `sphior-code-mcp/${CONFIG.version} node/${process.versions.node}`,
        },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      // ネットワーク / abort
      const msg = err instanceof Error ? err.message : String(err);
      throw new SphiorApiError(0, endpoint, `Network error: ${msg}`, "Check your internet connection and SPHIOR_API_BASE setting.");
    }
    clearTimeout(timer);

    if (!res.ok) {
      let errBody: { error?: string; hint?: string } = {};
      try { errBody = (await res.json()) as { error?: string; hint?: string }; } catch { /* non-JSON error body */ }
      const message = errBody.error ?? `HTTP ${res.status} ${res.statusText}`;
      const hint    = errBody.hint  ?? (res.status === 401
        ? "Verify SPHIOR_API_KEY is valid and not revoked."
        : res.status === 429
        ? "Rate limit exceeded. Retry after a few seconds."
        : undefined);
      throw new SphiorApiError(res.status, endpoint, message, hint);
    }

    log.debug(`← ${endpoint} 200`);
    return (await res.json()) as T;
  });
}

// ── Public API methods ────────────────────────────────────────────────────────

export const api = {
  listFindings(opts: { severity?: string; status?: string; limit?: number } = {}): Promise<{ findings: Finding[] }> {
    return request("/code/findings", { query: { severity: opts.severity, status: opts.status, limit: opts.limit } });
  },

  getFinding(findingId: string): Promise<{ finding: FindingDetail }> {
    return request(`/code/findings/${encodeURIComponent(findingId)}`);
  },

  getSummary(): Promise<{ summary: SecuritySummary }> {
    return request("/code/summary");
  },


  resolveFinding(findingId: string, reason?: string): Promise<{ message: string }> {
    return request(`/code/findings/${encodeURIComponent(findingId)}/resolve`, {
      method: "POST",
      body:   { reason },
    });
  },

  markFalsePositive(findingId: string, reason?: string): Promise<{ message: string }> {
    return request(`/code/findings/${encodeURIComponent(findingId)}/false-positive`, {
      method: "POST",
      body:   { reason },
    });
  },

  // 改ざん不可の監査証跡（決定論エンジン）の独立検証。監査人向け。
  verifyEvidence(opts: { repo?: string; includePack?: boolean } = {}): Promise<unknown> {
    return request("/code/evidence", { query: { repo: opts.repo, pack: opts.includePack ? "1" : undefined } });
  },

  // 決定論 finding の修正コンテキスト（顧客 AI が直すための payload・コード非送信）。
  getFixContext(opts: { repo?: string; findingId?: string; severity?: string } = {}): Promise<unknown> {
    return request("/code/evidence/fix-context", {
      query: { repo: opts.repo, finding_id: opts.findingId, severity: opts.severity },
    });
  },
};
