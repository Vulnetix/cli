package com.acme.net

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.tls.tls
import kotlinx.coroutines.Dispatchers
import kotlin.coroutines.coroutineContext

class SecureChat(private val host: String) {
    suspend fun open() {
        val selector = SelectorManager(Dispatchers.IO)
        val socket = aSocket(selector).tcp()
            .connect(host, 443)
            .tls(coroutineContext)
        socket.close()
    }
}
