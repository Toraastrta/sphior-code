/**
 * collect.ts — リポジトリ/ディレクトリからソースファイルを決定論的に収集
 *
 * CLI / GitHub Action / self-host が使う I/O 層。node:fs を同期で使う（CLI 用途）。
 * ignore ディレクトリ・バイナリ・サイズ超過を除外し、path 昇順で返す。
 */

import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { parseSphiorignore, EMPTY_CONFIG, SPHIORIGNORE_FILE, type SphiorignoreConfig } from "./suppress";

/**
 * 走査しないディレクトリ。**ビルド出力と取得済み依存だけ**を入れる。
 *
 * 入れてはいけないもの: 秘密が紛れ込む場所（`.env*`・`.vscode`・`*.example`・`.github`）。
 * 実際にこのリポジトリでも `.dev.vars.example` に本物の Stripe ライブキーが入っていた。
 * 「設定サンプルだから安全」という前提は置かない。
 */
const IGNORE_DIRS = new Set([
  // VCS
  ".git", ".hg", ".svn",
  // JS/TS の依存と出力
  "node_modules", "bower_components", ".yarn", ".pnp", ".pnpm-store",
  "dist", "build", "out", "coverage", ".cache", ".turbo", ".swc", ".parcel-cache",
  // フレームワーク/デプロイのビルド出力
  ".next", ".open-next", ".vercel", ".wrangler", ".serverless", ".sst",
  ".svelte-kit", ".nuxt", ".output", ".astro", ".docusaurus",
  // Python
  ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", ".eggs",
  // JVM / その他言語
  "target", ".gradle", "vendor", "Pods", ".dart_tool", ".pub-cache",
  // IaC のプロバイダバイナリ（`.tf` 本体は配下に無いので検査対象は失わない）
  ".terraform",
]);

export interface CollectOptions {
  maxBytes?: number; // 既定 512KB
  ignoreDirs?: Set<string>;
  /**
   * 追加のパス除外（`.sphiorignore` 由来）。走査ルート相対・POSIX 区切りで呼ばれる。
   * ファイルを読む前に落とすので、除外されたファイルからは finding が生まれない
   * （= 抑制ではなく「見なかった」。suppress.ts の冒頭コメント参照）。
   * 件数を数えたい呼び出し側はクロージャで包む。
   */
  exclude?: (relPath: string) => boolean;
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
        // ディレクトリ名そのものが除外に当たるなら枝ごと刈る（`Docs` 形式）。
        // `Docs/**` 形式はここでは当たらないが、下のファイル単位判定で同じ結果になる
        if (opts.exclude?.(toPosix(relative(rootDir, full)))) continue;
        walk(full);
      } else if (st.isFile()) {
        if (st.size > maxBytes) continue;
        if (opts.exclude?.(toPosix(relative(rootDir, full)))) continue;
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

/**
 * 走査ルート直下の `.sphiorignore` を読む（無ければ空設定）。
 * 解析自体は suppress.ts（純関数）。I/O はこの層に閉じる。
 */
export function readSphiorignore(rootDir: string): SphiorignoreConfig {
  try {
    return parseSphiorignore(readFileSync(join(rootDir, SPHIORIGNORE_FILE), "utf8"));
  } catch {
    return EMPTY_CONFIG; // 無い / 読めない = 設定なし
  }
}
