package com.acme.bridge

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.tls.tls
import kotlinx.coroutines.Dispatchers

suspend fun secureForward(host: String) {
    val selector = SelectorManager(Dispatchers.IO)
    val socket = aSocket(selector).tcp().connect(host, 8883).tls(Dispatchers.IO)
    socket.close()
}
