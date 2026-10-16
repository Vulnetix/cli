package com.acme.bridge

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Dispatchers

suspend fun forward(brokerHost: String, frame: String) {
    val selector = SelectorManager(Dispatchers.IO)
~>    val conn = aSocket(selector).tcp().connect(brokerHost, 1883)
    val out = conn.openWriteChannel(autoFlush = true)
    out.writeStringUtf8(frame)
    conn.close()
}
