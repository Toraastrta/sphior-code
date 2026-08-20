/**
 * rules.ts — 決定論的シークレット検出ルール（プロバイダ署名）
 *
 * 高信頼（プロバイダ固有 prefix）を中心に構成し、誤検知を抑える。
 * 生値の検証（verified secret）は別途 opt-in（設計 §4.2）。
 * CWE-798: Use of Hard-coded Credentials。
 */

import type { Severity } from "../types";

export interface SecretRule {
  id: string; // 安定 rule id（証跡に刻む）
  provider: string;
  title: string;
  severity: Severity;
  /** グローバルマッチ用。1つのキャプチャ or 全体一致で秘密実体を取る。 */
  pattern: RegExp;
  /** マッチ全体でなく group[n] を秘密実体とする場合に指定。 */
  group?: number;
  references?: string[];
}

// 既知のドキュメント用プレースホルダ（誤検知として除外）
export const PLACEHOLDER_SECRETS = new Set<string>([
  "AKIAIOSFODNN7EXAMPLE", // AWS 公式ドキュメントの例
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
]);

const REF_CWE798 = ["https://cwe.mitre.org/data/definitions/798.html"];

export const SECRET_RULES: SecretRule[] = [
  {
    id: "secret.aws.access_key_id",
    provider: "AWS",
    title: "AWS Access Key ID",
    severity: "high",
    pattern: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.github.pat",
    provider: "GitHub",
    title: "GitHub Personal Access Token",
    severity: "critical",
    pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.github.fine_grained_pat",
    provider: "GitHub",
    title: "GitHub Fine-grained PAT",
    severity: "critical",
    pattern: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.stripe.live",
    provider: "Stripe",
    title: "Stripe Live Secret Key",
    severity: "critical",
    pattern: /\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.stripe.test",
    provider: "Stripe",
    title: "Stripe Test Secret Key",
    severity: "low",
    pattern: /\b((?:sk|rk)_test_[A-Za-z0-9]{24,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.google.api_key",
    provider: "Google",
    title: "Google API Key",
    severity: "high",
    pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.slack.token",
    provider: "Slack",
    title: "Slack Token",
    severity: "high",
    pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.slack.webhook",
    provider: "Slack",
    title: "Slack Incoming Webhook",
    severity: "medium",
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+)/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.openai.key",
    provider: "OpenAI",
    title: "OpenAI API Key",
    severity: "high",
    pattern: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.anthropic.key",
    provider: "Anthropic",
    title: "Anthropic API Key",
    severity: "high",
    pattern: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.sendgrid.key",
    provider: "SendGrid",
    title: "SendGrid API Key",
    severity: "high",
    pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.twilio.api_key",
    provider: "Twilio",
    title: "Twilio API Key",
    severity: "high",
    pattern: /\b(SK[0-9a-fA-F]{32})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.npm.token",
    provider: "npm",
    title: "npm Access Token",
    severity: "high",
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.jwt",
    provider: "JWT",
    title: "JSON Web Token",
    severity: "medium",
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.private_key",
    provider: "PEM",
    title: "Private Key",
    severity: "critical",
    pattern: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.gitlab.pat",
    provider: "GitLab",
    title: "GitLab Personal Access Token",
    severity: "critical",
    pattern: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.digitalocean.pat",
    provider: "DigitalOcean",
    title: "DigitalOcean Personal Access Token",
    severity: "critical",
    pattern: /\b(dop_v1_[a-f0-9]{64})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.shopify.token",
    provider: "Shopify",
    title: "Shopify Access Token",
    severity: "high",
    pattern: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.square.token",
    provider: "Square",
    title: "Square Access Token",
    severity: "high",
    pattern: /\b(sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.mailchimp.key",
    provider: "Mailchimp",
    title: "Mailchimp API Key",
    severity: "high",
    pattern: /\b([0-9a-f]{32}-us[0-9]{1,2})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.discord.bot_token",
    provider: "Discord",
    title: "Discord Bot Token",
    severity: "high",
    pattern: /\b([MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.databricks.token",
    provider: "Databricks",
    title: "Databricks Personal Access Token",
    severity: "high",
    pattern: /\b(dapi[0-9a-f]{32})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.linear.key",
    provider: "Linear",
    title: "Linear API Key",
    severity: "high",
    pattern: /\b(lin_api_[A-Za-z0-9]{40})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.postman.key",
    provider: "Postman",
    title: "Postman API Key",
    severity: "high",
    pattern: /\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.hashicorp.vault_token",
    provider: "HashiCorp Vault",
    title: "HashiCorp Vault Token",
    severity: "critical",
    pattern: /\b(hvs\.[A-Za-z0-9_-]{24,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.grafana.token",
    provider: "Grafana",
    title: "Grafana Cloud Token",
    severity: "high",
    pattern: /\b(glc_[A-Za-z0-9+/=]{32,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.slack.app_token",
    provider: "Slack",
    title: "Slack App-Level Token",
    severity: "high",
    pattern: /\b(xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+)\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.sentry.token",
    provider: "Sentry",
    title: "Sentry Auth Token",
    severity: "high",
    pattern: /\b(sntrys_[A-Za-z0-9+/=]{40,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.pypi.token",
    provider: "PyPI",
    title: "PyPI Upload Token",
    severity: "critical",
    pattern: /\b(pypi-[A-Za-z0-9_-]{50,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.doppler.token",
    provider: "Doppler",
    title: "Doppler Token",
    severity: "critical",
    pattern: /\b(dp\.(?:pt|st|ct|sa)\.[A-Za-z0-9]{40,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.terraform.cloud_token",
    provider: "Terraform Cloud",
    title: "Terraform Cloud API Token",
    severity: "critical",
    pattern: /\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.newrelic.key",
    provider: "New Relic",
    title: "New Relic API Key",
    severity: "high",
    pattern: /\b(NRAK-[A-Z0-9]{27})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.sonarqube.token",
    provider: "SonarQube",
    title: "SonarQube Token",
    severity: "high",
    pattern: /\b(squ_[a-f0-9]{40})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.figma.token",
    provider: "Figma",
    title: "Figma Personal Access Token",
    severity: "high",
    pattern: /\b(figd_[A-Za-z0-9_-]{40,})\b/g,
    group: 1,
    references: REF_CWE798,
  },
  {
    id: "secret.telegram.bot_token",
    provider: "Telegram",
    title: "Telegram Bot Token",
    severity: "high",
    pattern: /\b(\d{8,10}:AA[A-Za-z0-9_-]{32,34})\b/g,
    group: 1,
    references: REF_CWE798,
  },
];

/**
 * 汎用高エントロピー割当（context 依存・needs_review）。
 * 例: `api_key = "aG9...long..."`。エントロピーで最終判定する。
 */
export const GENERIC_ASSIGNMENT = {
  id: "secret.generic.high_entropy_assignment",
  provider: "Generic",
  title: "Possible hard-coded secret (high entropy)",
  severity: "medium" as Severity,
  // key 名 + クオート値
  pattern:
    /(?:secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|auth|credential)["'\s]*[:=]\s*["'`]([^"'`\n]{16,})["'`]/gi,
  references: REF_CWE798,
};
