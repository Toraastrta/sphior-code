package com.sphior.code

import com.intellij.openapi.project.Project
import com.redhat.devtools.lsp4ij.LanguageServerFactory
import com.redhat.devtools.lsp4ij.server.StreamConnectionProvider

/**
 * LSP4IJ に SPHIOR CODE の LSP サーバを提供するファクトリ。
 * plugin.xml の <server factoryClass="..."> から参照される。
 */
class SphiorLspServerFactory : LanguageServerFactory {
    override fun createConnectionProvider(project: Project): StreamConnectionProvider =
        SphiorLspServer(project)
}
