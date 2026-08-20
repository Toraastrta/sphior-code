package com.sphior.code

import java.io.File

/**
 * Node.js 実行ファイルの解決。
 *
 * GUI から起動した IDE はログインシェルの PATH を継承しないことが多い（特に macOS）。
 * そのため「node は入っているのにプラグインからは見つからない」が最も多い失敗パターンで、
 * PATH だけを見ると誤って「未インストール」と報告してしまう。よくある導入先まで探しに行く。
 *
 * 探索順:
 *   1. SPHIOR_NODE_PATH（利用者の明示指定が最優先）
 *   2. PATH 上の node
 *   3. よくある導入先（Homebrew / Volta / fnm / nvm / システム / Windows 標準）
 */
object NodeResolver {

    private val isWindows: Boolean
        get() = System.getProperty("os.name").orEmpty().lowercase().contains("win")

    private val binaryName: String
        get() = if (isWindows) "node.exe" else "node"

    /** 実行可能な node の絶対パス。見つからなければ null。 */
    fun resolve(): String? =
        fromExplicitEnv() ?: fromPath() ?: fromCommonLocations()

    /** 利用者が明示指定した実行ファイル。 */
    private fun fromExplicitEnv(): String? =
        System.getenv("SPHIOR_NODE_PATH")
            ?.takeIf { it.isNotBlank() }
            ?.let { File(it) }
            ?.takeIf { it.canExecute() }
            ?.absolutePath

    /** PATH 上の node（IDE が PATH を継承していれば通常はここで見つかる）。 */
    private fun fromPath(): String? =
        System.getenv("PATH")
            ?.split(File.pathSeparator)
            ?.asSequence()
            ?.filter { it.isNotBlank() }
            ?.map { File(it, binaryName) }
            ?.firstOrNull { it.canExecute() }
            ?.absolutePath

    /** バージョンマネージャ等のよくある導入先。PATH 非継承時の救済。 */
    private fun fromCommonLocations(): String? {
        val home = System.getProperty("user.home").orEmpty()
        val candidates = mutableListOf<File>()

        if (isWindows) {
            candidates += File("C:\\Program Files\\nodejs\\node.exe")
            candidates += File("C:\\Program Files (x86)\\nodejs\\node.exe")
            candidates += File(home, "AppData\\Roaming\\npm\\node.exe")
        } else {
            candidates += File("/opt/homebrew/bin/node")   // Homebrew (Apple Silicon)
            candidates += File("/usr/local/bin/node")      // Homebrew (Intel) / 手動導入
            candidates += File("/usr/bin/node")            // ディストリのパッケージ
            candidates += File(home, ".volta/bin/node")    // Volta
            candidates += File(home, ".local/bin/node")
            // nvm / fnm はバージョンごとにディレクトリが分かれる。新しい順に探す。
            candidates += versionedCandidates(File(home, ".nvm/versions/node"))
            candidates += versionedCandidates(File(home, ".fnm/node-versions"), "installation/bin")
            candidates += versionedCandidates(File(home, "Library/Application Support/fnm/node-versions"), "installation/bin")
        }
        return candidates.firstOrNull { it.canExecute() }?.absolutePath
    }

    /** `<root>/<version>/<sub>/node` を新しいバージョン順に列挙する。 */
    private fun versionedCandidates(root: File, sub: String = "bin"): List<File> {
        if (!root.isDirectory) return emptyList()
        return root.listFiles()
            ?.filter { it.isDirectory }
            ?.sortedByDescending { it.name }   // v22 > v20 > v18（文字列順で概ね新しい順）
            ?.map { File(it, "$sub/$binaryName") }
            ?: emptyList()
    }
}
