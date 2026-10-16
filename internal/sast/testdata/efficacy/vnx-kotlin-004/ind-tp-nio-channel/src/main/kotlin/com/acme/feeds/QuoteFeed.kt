package com.acme.feeds

import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel

class QuoteFeed(private val upstream: String) {
    fun subscribe(symbol: String) {
~>        val channel = SocketChannel.open(InetSocketAddress(upstream, 6000))
        channel.write(ByteBuffer.wrap("SUB $symbol\n".toByteArray()))
        channel.close()
    }
}
