package com.acme.ingest

import java.net.InetSocketAddress
import java.nio.channels.ServerSocketChannel

fun openIngest(port: Int): ServerSocketChannel {
    val channel = ServerSocketChannel.open()
~>    channel.bind(InetSocketAddress("0.0.0.0", port))
    channel.configureBlocking(false)
    return channel
}
