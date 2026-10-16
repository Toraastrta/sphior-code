/*
 * SPHIOR CODE — JetBrains plugin build (IntelliJ Platform Gradle Plugin 2.x)
 *
 * LSP4IJ 経由で @sphior/scan の LSP サーバ(server.cjs)に接続し、
 * 決定論スキャン(secrets + CWE)の診断を全 JetBrains IDE で表示する。
 *
 * NOTE: バージョン(IDE/LSP4IJ/Gradle plugin)は環境に合わせて更新可。
 */

plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "2.0.21"
    id("org.jetbrains.intellij.platform") version "2.1.0"
}

group = "com.sphior"
version = "0.1.1"

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        // 幅広い IDE を狙うため Community をターゲット（全 JetBrains IDE 上位互換）
        intellijIdeaCommunity("2024.2")
        // LSP4IJ（LSP を IntelliJ に載せるプラグイン）に依存
        plugin("com.redhat.devtools.lsp4ij", "0.7.0")
        // instrumentCode タスクが要求する Java Compiler（Gradle plugin 2.1.0 の必須依存）
        instrumentationTools()
        // verifyPlugin タスクが使う Plugin Verifier CLI
        pluginVerifier()
    }
}

intellijPlatform {
    // publishPlugin にトークンの受け取り口が無く `-Ptoken=` が無視されていたので配線する
    // （BUILD.md はこの書き方を前提に書かれていた）。環境変数でも渡せるようにしておく。
    publishing {
        token = providers.gradleProperty("token")
            .orElse(providers.environmentVariable("JETBRAINS_MARKETPLACE_TOKEN"))
    }
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "242"
            // 上限を設けない（新 IDE でも動くように）。審査で必要なら固定する。
            untilBuild = provider { null }
        }
    }
    pluginVerification {
        ides {
            // Marketplace 審査と同じ Plugin Verifier。recommended() は未配布バージョンを
            // 引いて解決失敗することがあるため、実在バージョンを明示ピンする
            ide(org.jetbrains.intellij.platform.gradle.IntelliJPlatformType.IntellijIdeaCommunity, "2024.2")
            ide(org.jetbrains.intellij.platform.gradle.IntelliJPlatformType.IntellijIdeaCommunity, "2025.1")
        }
    }
}

// IntelliJ Platform 2024.2+ は Java 21 を要求
kotlin {
    jvmToolchain(21)
}

// ── LSP サーバの同梱を自動化 ──────────────────────────────────────────────────
// src/main/resources/server/server.cjs は @sphior/scan の生成物で、手で
// `node scripts/copy-server.mjs` を叩く運用だった。VS Code 拡張は npm run build が
// 自動で同期するのに、こちらだけ手動だったためエンジン更新時に取り残される
// （実際 2026-10-16 時点で 9/5 のまま取り残されていた）。
// processResources に前置して、ビルドのたびに必ず最新が入るようにする。
val syncLspServer by tasks.registering(Exec::class) {
    group = "build"
    description = "@sphior/scan の server.cjs を resources へ同期する"
    workingDir = projectDir
    commandLine("node", "scripts/copy-server.mjs")

    // 入出力を宣言して up-to-date 判定を効かせる（毎回 30MB コピーしない）
    inputs.file(projectDir.resolve("../sphior-scan/dist/server.cjs"))
    outputs.file(projectDir.resolve("src/main/resources/server/server.cjs"))

    // @sphior/scan が未ビルドなら、理由を明示して止める（黙って古い物を同梱しない）
    doFirst {
        val engine = projectDir.resolve("../sphior-scan/dist/server.cjs")
        if (!engine.exists()) {
            throw GradleException(
                "LSP サーバが見つかりません: $engine\n" +
                "  → packages/sphior-scan で `npm run build` を先に実行してください。",
            )
        }
    }
}

tasks.named("processResources") { dependsOn(syncLspServer) }
