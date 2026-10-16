package com.acme.ctl

import java.net.InetSocketAddress
import java.nio.channels.ServerSocketChannel

class AdminChannel(private val adminPort: Int) {
    fun open(): ServerSocketChannel {
~>        val adminChannel = ServerSocketChannel.open().bind(InetSocketAddress(adminPort))
        adminChannel.configureBlocking(false)
        return adminChannel
    }
}
