/**
 * gen-notices.mjs — バンドルした依存のライセンス表示を THIRD-PARTY-NOTICES.md に集める
 *
 * なぜ必要か:
 *   dist/*.js は esbuild で依存を丸ごと取り込んだ単一ファイル。MIT を含む多くの
 *   ライセンスは「複製物および実質的な部分に著作権表示を含めること」を配布条件に
 *   しているので、バンドル配布では表示を別の形で同梱しなければならない。
 *   上流の多くは LICENSE を別ファイルで配っており（ソース中に @license コメントを
 *   置かない）、esbuild の legalComments では拾えない。だからここで集める。
 *
 *   監査証跡を売っている以上、自分の配布物のライセンス順守が崩れているのは筋が通らない。
 *
 * 集める対象: package.json の dependencies（devDependencies はバンドルされないので対象外）。
 * LICENSE ファイルが無いパッケージは、宣言ライセンスと参照先を記録して「不明のまま
 * 黙って配る」ことを避ける。
 */

import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

/** node_modules/<name>/ から LICENSE 系ファイルを 1 つ探す。 */
function findLicenseFile(dir) {
  if (!existsSync(dir)) return null;
  const hit = readdirSync(dir).find((f) => /^(LICENSE|LICENCE|COPYING)(\.|$)/i.test(f));
  return hit ? join(dir, hit) : null;
}

function repoUrl(meta) {
  const r = meta.repository;
  if (!r) return meta.homepage ?? null;
  const url = typeof r === "string" ? r : r.url;
  return url ? url.replace(/^git\+/, "").replace(/\.git$/, "") : null;
}

const sections = [];
const missing = [];

for (const name of Object.keys(pkg.dependencies ?? {})) {
  const dir = join(root, "node_modules", name);
  const metaPath = join(dir, "package.json");
  if (!existsSync(metaPath)) {
    missing.push(`${name} (未インストール — npm install してから再生成すること)`);
    continue;
  }
  const meta = JSON.parse(readFileSync(metaPath, "utf8"));
  const license = typeof meta.license === "string" ? meta.license : (meta.license?.type ?? "UNKNOWN");
  const url = repoUrl(meta);
  const licFile = findLicenseFile(dir);

  let body;
  if (licFile) {
    body = readFileSync(licFile, "utf8").trim();
  } else {
    // 全文が無い場合は捏造せず、宣言ライセンスと参照先だけを記録する
    missing.push(`${name} (${license} — LICENSE 全文が配布物に含まれていない)`);
    body = `Licensed under ${license}.\nNo license text is shipped with this package; see ${url ?? "the package repository"}.`;
  }

  sections.push(
    `## ${name}@${meta.version}\n\n` +
    `License: ${license}${url ? `\nSource: ${url}` : ""}\n\n` +
    "```\n" + body + "\n```\n",
  );
}

const out =
  "# Third-party notices\n\n" +
  "<!-- 生成物。手で編集しない。`npm run build`（gen-notices.mjs）が作り直す。 -->\n\n" +
  "`@sphior/scan` ships as a bundled single file, so the following dependencies are\n" +
  "compiled into `dist/`. Their license terms and copyright notices are reproduced here.\n\n" +
  sections.join("\n") +
  (missing.length
    ? "\n## Notes\n\n" + missing.map((m) => `- ${m}`).join("\n") + "\n"
    : "");

writeFileSync(join(root, "THIRD-PARTY-NOTICES.md"), out);
console.log(
  `[sphior-scan] third-party notices written (${sections.length} deps` +
  (missing.length ? `, ${missing.length} without full text` : "") + ")",
);
