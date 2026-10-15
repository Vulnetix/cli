package io.acme.relay

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openWriteChannel
import kotlinx.coroutines.Dispatchers

suspend fun relay(upstream: String, body: ByteArray) {
    val selector = SelectorManager(Dispatchers.IO)
~>    val socket = aSocket(selector).tcp()
        .connect(upstream, 7000)
    val out = socket.openWriteChannel(autoFlush = true)
    out.writeFully(body)
}
