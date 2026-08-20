package com.sphior.code

import com.intellij.ide.BrowserUtil
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.project.Project
import com.redhat.devtools.lsp4ij.server.ProcessStreamConnectionProvider
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * SPHIOR CODE の LSP サーバ接続プロバイダ。
 *
 * 同梱した @sphior/scan の `server.cjs`（resources 内）を一時ファイルへ展開し、
 * `node server.cjs --stdio` を spawn して stdio で接続する。ソースは端末外へ
 * 送らない（ローカル完結・§0.6）。
 *
 * Node.js が見つからない場合は「無言で失敗」させない。GUI 起動の IDE は PATH を
 * 継承しないことが多く、原因が利用者に伝わらないと ★1 レビューに直結するため、
 * 実行可能な node を能動的に探し（[NodeResolver]）、それでも無ければ理由と対処を
 * 通知する。
 */
class SphiorLspServer(private val project: Project) : ProcessStreamConnectionProvider() {

    init {
        val node = NodeResolver.resolve()
        if (node == null) {
            notifyNodeMissing()
            error(
                "SPHIOR CODE: Node.js was not found. Install Node.js (https://nodejs.org) or set the " +
                    "SPHIOR_NODE_PATH environment variable to the full path of the node executable.",
            )
        }
        val server = extractBundledServer()
        super.setCommands(listOf(node, server.absolutePath, "--stdio"))
    }

    /** 原因と対処を利用者に伝える（バルーン通知）。黙って動かないのを避ける。 */
    private fun notifyNodeMissing() {
        NotificationGroupManager.getInstance()
            .getNotificationGroup(NOTIFICATION_GROUP)
            .createNotification(
                "SPHIOR CODE: Node.js not found",
                "SPHIOR CODE needs Node.js to run its local analysis engine, but no executable was found.<br><br>" +
                    "Install Node.js, or set <code>SPHIOR_NODE_PATH</code> to the full path of your " +
                    "<code>node</code> binary and restart the IDE.<br><br>" +
                    "If Node.js is already installed, your IDE may not have inherited your shell PATH — " +
                    "setting <code>SPHIOR_NODE_PATH</code> resolves that case.",
                NotificationType.WARNING,
            )
            .addAction(NotificationAction.createSimple("Download Node.js") { BrowserUtil.browse("https://nodejs.org") })
            .notify(project)
    }

    /** jar 内 resources の server.cjs を一時ファイルへ展開して返す。 */
    private fun extractBundledServer(): File {
        val dir = Files.createTempDirectory("sphior-lsp").toFile().apply { deleteOnExit() }
        val out = File(dir, "server.cjs").apply { deleteOnExit() }
        val input = javaClass.getResourceAsStream("/server/server.cjs")
            ?: error("SPHIOR CODE: bundled LSP server (/server/server.cjs) not found in plugin resources")
        input.use { Files.copy(it, out.toPath(), StandardCopyOption.REPLACE_EXISTING) }
        return out
    }

    private companion object {
        const val NOTIFICATION_GROUP = "SPHIOR CODE"
    }
}
