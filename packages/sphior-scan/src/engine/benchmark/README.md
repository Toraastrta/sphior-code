# SPHIOR CODE SAST — OWASP Benchmark 測定パイプライン

SPHIOR CODE の**本番 SaaS スキャンエンジン**（`src/lib/scan` の `runScan`。GitHub App の
PR/push スキャンが使う決定論エンジン）を OWASP Benchmark にかけ、**TPR / FPR / F1 / Youden J**
を実測する。「誤検知と検知漏れのバランスをどう取ったか」に主観でなく数値で答えるための計測器。

> 対象は SaaS 側 regex コアエンジン。CLI/LSP 配布物 `packages/sphior-scan`（tree-sitter taint）は
> 別エンジンのため、この計測器の対象外（必要なら別ハーネスを足す）。

## 何を測るか

各テストケースは 1 カテゴリ + `real vulnerability` ラベルを持つ。当該ファイルにそのカテゴリの
CWE を報告できたかで混同行列を作る（OWASP Benchmark 公式方法論）:

| | 検出した | 検出しない |
|---|---|---|
| **実際に脆弱** | TP | FN（検知漏れ） |
| **安全な変種** | FP（誤検知） | TN |

- **TPR** = TP/(TP+FN) … 検知できた割合（高いほど良い）
- **FPR** = FP/(FP+TN) … 安全変種を誤検知した割合（低いほど良い）
- **Youden J** = TPR − FPR … OWASP Benchmark スコア（高いほど良い）
- **F1** = 2·precision·recall/(precision+recall)

分母 0 の指標は捏造せず `—`。

## 使い方

### スモーク（Benchmark 不要）

```bash
npm run benchmark:sast
```

合成 E2E のみ実行。本番エンジンに実 Java スニペットを通し、CWE→カテゴリ→採点までの
一気通貫が壊れていないことを検証する（実 Benchmark が無くてもパイプラインの正しさを保証）。

### 実 Benchmark で基準値を取る

1. Benchmark を**リポジトリ外**にチェックアウト（本リポには含めない）:

   ```bash
   git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git /tmp/BenchmarkJava
   ```

2. `BENCHMARK_DIR` で指して実行:

   ```bash
   BENCHMARK_DIR=/tmp/BenchmarkJava npm run benchmark:sast
   ```

   - ルート直下の `expectedresults*.csv` と
     `src/main/java/org/owasp/benchmark/testcase/*.java` を自動探索する。
   - カテゴリ別 + 全体の表をコンソール出力し、`benchmark-sast-result.json` を保存
     （保存先は `BENCHMARK_OUT` で変更可）。
   - レイアウトが非標準なら `expectedCsvPath` / `testcaseDir` を `runBenchmark()` に渡す。

## 現状の Java カバレッジ（着手前の既知）

本番 regex コアの Java ルールは cmdi(CWE-78) / sqli(CWE-89) / crypto・hash(CWE-327) /
**pathtraver(CWE-22・連結) / ldapi(CWE-90・連結) / xpathi(CWE-643・連結) / weakrand(CWE-330) /
securecookie(CWE-614)** を検出する（連結系は高シグナル形に限定して FP を抑制）。**trustbound(CWE-501)
は構造的な信頼境界解析が要るため regex では未実装**（IaC/アーキ解析向き）。xss は部分実装。
最終的な TPR/FPR は実 Benchmark で確定する（＝実測）。`uncoveredCategories` に残るカテゴリから
1 つずつルールを足し、再測定して潰す（PDCA）。

## 分野別採点器（SAST/DAST/SCA/IaC を同一の指標定義で測る）

同じ混同行列の数理（`score.ts` の `metricsOf`）を全分野で再利用し、指標定義を単一化する（PLAN P0）。
軸だけが分野で異なる:

| 分野 | 採点器 | 照合軸（同一性キー） | 群 | 出口の実測（本節の対象外＝残） |
|---|---|---|---|---|
| SAST | `score.ts` + `categories.ts` | ファイル×CWE カテゴリ（OWASP 公式） | カテゴリ | OWASP Benchmark |
| DAST | `dast-benchmark.ts` | URL×CWE | カテゴリ | WAVSEP / Juice Shop |
| SCA | `sca-benchmark.ts` | `ecosystem:pkg@version`（**版境界**） | ecosystem | 既知脆弱 lockfile 群 |
| IaC | `iac-benchmark.ts` | `RULEID@resource` | provider | 意図的脆弱構成群 |

SCA/IaC は CWE カテゴリでなく安定キーの同一性で測るため、共通土台 `identity-score.ts`（`scoreIdentity`）に
混同行列採点を集約する。**採点器はすべて純関数で本セッションで完成済み**。各分野に残るのは「正解付き実コーパスを
用意してエンジンを実走させ数値を出す」実測のみ（外部コーパス・実行環境が要るため本リポには含めない）。

## ファイル構成

| ファイル | 役割 |
|---|---|
| `categories.ts` | カテゴリ↔CWE 集合。表記ゆらぎ（弱ハッシュ=327）を吸収 |
| `expected-results.ts` | expectedresults CSV パーサ（堅牢・未知行は skip 可視化） |
| `score.ts` | 混同行列 + 指標（純関数・I/O なし・全分野共通） |
| `identity-score.ts` | 同一性照合ベースの群別採点（SCA/IaC 共通土台・純関数） |
| `dast-benchmark.ts` | DAST 採点器（URL×CWE 突合・純関数） |
| `sca-benchmark.ts` | SCA 採点器（版マッチ境界・純関数） |
| `iac-benchmark.ts` | IaC 採点器（ルール×リソース突合・純関数） |
| `run-benchmark.ts` | SAST 実 Benchmark 走査（`node:fs`・server/CLI 専用） |
| `run-dast-benchmark.ts` | DAST 実走ドライバ（正解+ランナー出力を採点・`DAST_BENCH_DIR`） |
| `run-iac-benchmark.ts` | IaC 実走ドライバ（Trivy JSON→アダプタ→採点・`IAC_BENCH_DIR`） |
| `report.ts` / `grouped-report.ts` | コンソール表整形（カテゴリ別 / 群別） |
| `run-benchmark.test.ts` | 合成 E2E（常時）+ 実 Benchmark（`BENCHMARK_DIR` 時） |
| `run-{dast,iac}-benchmark.test.ts` | 合成 E2E（常時）+ 実コーパス（`{DAST,IAC}_BENCH_DIR` 時）。`npm run measure:{dast,iac}` |
| `__tests__/{identity,sca,iac}-benchmark.test.ts` | 各採点器の合成 fixture 検証（版/リソース境界を固定） |

各実走ドライバは SAST(`run-benchmark`)と同じ 2 モード: **常時=合成スモークで配線を保証 / 環境変数でコーパス指定時のみ実走**。
エンジン実行（ZAP/Nuclei/Trivy バイナリ）は外部境界で、ドライバは「正解 × エンジン出力の採点」を所有する。
残るのは実コーパス投入＝**実測**のみ。
