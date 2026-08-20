/**
 * measure-java-taint.ts — CLI package の Java taint を実 OWASP Benchmark に直当てして採点する
 * standalone 計測（本番無風・A1 統合の価値を先に確定する）。
 *
 * Java taint がカバーする cmdi(CWE-78)/sqli(CWE-89)/pathtraver(CWE-22) のみを対象に、
 * regex ベースライン(全て 0%)と比較する。実行: BENCHMARK_DIR=/path node <bundled>.cjs
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { initJava } from "../src/java-ast";
import { getAstBackend } from "../src/engine/patterns/ast-backend";

const DIR = process.env.BENCHMARK_DIR;
if (!DIR) { console.error("BENCHMARK_DIR required"); process.exit(1); }

const CAT_CWE: Record<string, number> = { cmdi: 78, sqli: 89, pathtraver: 22 };
const csv = readFileSync(join(DIR, "expectedresults-1.2.csv"), "utf8");
const testcaseDir = join(DIR, "src", "main", "java", "org", "owasp", "benchmark", "testcode");

const rows = csv.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
  .filter((l) => !/^#/.test(l) && !/^test\s*name/i.test(l))
  .map((l) => { const [name, cat, real] = l.split(",").map((s) => s.trim()); return { name, cat, real: real === "true" }; })
  .filter((r) => CAT_CWE[r.cat] != null);

async function main() {
  await initJava();
  const backend = getAstBackend("java");
  if (!backend) throw new Error("java backend not registered");

  const cm: Record<string, { tp: number; fp: number; fn: number; tn: number }> = {};
  for (const cat of Object.keys(CAT_CWE)) cm[cat] = { tp: 0, fp: 0, fn: 0, tn: 0 };
  let missing = 0;

  for (const r of rows) {
    const f = join(testcaseDir, r.name + ".java");
    if (!existsSync(f)) { missing++; continue; }
    const findings = backend.detect(r.name + ".java", readFileSync(f, "utf8"));
    const cwes = new Set(findings.map((x) => parseInt(String(x.cwe ?? "").replace(/\D/g, ""), 10) || 0));
    const detected = cwes.has(CAT_CWE[r.cat]);
    const c = cm[r.cat];
    if (r.real) { detected ? c.tp++ : c.fn++; } else { detected ? c.fp++ : c.tn++; }
  }

  const pct = (n: number, d: number) => (d === 0 ? "—" : ((n / d) * 100).toFixed(1) + "%");
  const tot = { tp: 0, fp: 0, fn: 0, tn: 0 };
  console.log("Java taint on OWASP Benchmark (cmdi/sqli/pathtraver) — missing files:", missing);
  console.log("category      TP  FP  FN  TN   TPR     FPR");
  for (const cat of Object.keys(CAT_CWE)) {
    const c = cm[cat]; tot.tp += c.tp; tot.fp += c.fp; tot.fn += c.fn; tot.tn += c.tn;
    console.log(
      `${cat.padEnd(12)} ${String(c.tp).padStart(3)} ${String(c.fp).padStart(3)} ${String(c.fn).padStart(3)} ${String(c.tn).padStart(3)}  ` +
      `${pct(c.tp, c.tp + c.fn).padStart(6)}  ${pct(c.fp, c.fp + c.tn).padStart(6)}`,
    );
  }
  console.log(
    `${"OVERALL".padEnd(12)} ${String(tot.tp).padStart(3)} ${String(tot.fp).padStart(3)} ${String(tot.fn).padStart(3)} ${String(tot.tn).padStart(3)}  ` +
    `${pct(tot.tp, tot.tp + tot.fn).padStart(6)}  ${pct(tot.fp, tot.fp + tot.tn).padStart(6)}`,
  );
}

main().catch((e) => { console.error(e); process.exit(1); });
