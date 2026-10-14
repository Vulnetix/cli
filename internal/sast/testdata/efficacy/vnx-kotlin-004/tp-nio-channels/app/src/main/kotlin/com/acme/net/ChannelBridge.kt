package com.acme.net

import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel

class ChannelBridge(private val upstream: String) {
    fun forward(data: ByteBuffer) {
~>        val channel = SocketChannel.open(InetSocketAddress(upstream, 6000))
        channel.write(data)
    }

    fun accept(port: Int) {
~>        val server = ServerSocketChannel.open().bind(InetSocketAddress(port))
        server.accept()
    }
}
