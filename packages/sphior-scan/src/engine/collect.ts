/**
 * collect.ts — リポジトリ/ディレクトリからソースファイルを決定論的に収集
 *
 * CLI / GitHub Action / self-host が使う I/O 層。node:fs を同期で使う（CLI 用途）。
 * ignore ディレクトリ・バイナリ・サイズ超過を除外し、path 昇順で返す。
 */

import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const IGNORE_DIRS = new Set([
  ".git", "node_modules", "dist", "build", ".next", "out", "coverage",
  "vendor", ".venv", "venv", "__pycache__", "target", ".turbo", ".cache",
  ".yarn", ".pnp", "bower_components",
]);

export interface CollectOptions {
  maxBytes?: number; // 既定 512KB
  ignoreDirs?: Set<string>;
}

export interface CollectedFile {
  path: string; // rootDir 相対・POSIX 区切り
  text: string;
}

function toPosix(p: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

/** バイナリ判定（NUL バイトを含む）。 */
function isBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

export function collectSourceFiles(rootDir: string, opts: CollectOptions = {}): CollectedFile[] {
  const maxBytes = opts.maxBytes ?? 512 * 1024;
  const ignore = opts.ignoreDirs ?? IGNORE_DIRS;
  const files: CollectedFile[] = [];

  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort()) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (ignore.has(name)) continue;
        walk(full);
      } else if (st.isFile()) {
        if (st.size > maxBytes) continue;
        let buf: Buffer;
        try {
          buf = readFileSync(full);
        } catch {
          continue;
        }
        if (isBinary(buf)) continue;
        files.push({ path: toPosix(relative(rootDir, full)), text: buf.toString("utf8") });
      }
    }
  };
  walk(rootDir);

  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return files;
}
