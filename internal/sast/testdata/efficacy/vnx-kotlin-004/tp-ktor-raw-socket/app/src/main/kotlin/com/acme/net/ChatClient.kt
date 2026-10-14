package com.acme.net

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Dispatchers

class ChatClient(private val host: String) {
    suspend fun send(token: String) {
        val selector = SelectorManager(Dispatchers.IO)
~>        val socket = aSocket(selector).tcp().connect(host, 9002)
        socket.openWriteChannel(autoFlush = true).writeStringUtf8("AUTH $token\n")
    }

    suspend fun serve() {
        val selector = SelectorManager(Dispatchers.IO)
~>        val server = aSocket(selector).tcp().bind("0.0.0.0", 9002)
        while (true) {
            val client = server.accept()
            println(client.remoteAddress)
        }
    }
}
