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
version = "0.1.0"

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
