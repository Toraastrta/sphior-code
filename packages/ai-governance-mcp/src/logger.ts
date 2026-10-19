/**
 * logger.ts — stderr-only logger (MCP の stdout を汚さない)。
 * MCP は stdout 上で JSON-RPC を交換するため console.log 厳禁。ログは全て stderr。
 */

import { CONFIG } from "./config.js";

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 } as const;
type Level = keyof typeof LEVELS;

function shouldLog(level: Level): boolean {
  const threshold = CONFIG.debug ? LEVELS.debug : LEVELS.info;
  return LEVELS[level] <= threshold;
}

function write(level: Level, message: string, meta?: Record<string, unknown>): void {
  if (!shouldLog(level)) return;
  const ts = new Date().toISOString();
  const extra = meta ? ` ${JSON.stringify(meta)}` : "";
  process.stderr.write(`${ts} [sphior-ai-governance-mcp] ${level.toUpperCase()} ${message}${extra}\n`);
}

export const log = {
  error: (msg: string, meta?: Record<string, unknown>): void => write("error", msg, meta),
  warn:  (msg: string, meta?: Record<string, unknown>): void => write("warn",  msg, meta),
  info:  (msg: string, meta?: Record<string, unknown>): void => write("info",  msg, meta),
  debug: (msg: string, meta?: Record<string, unknown>): void => write("debug", msg, meta),
};
