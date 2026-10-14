package com.acme.net

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

class CommandServer {
    fun listen() {
~>        val server = ServerSocket(9090)
        while (true) {
            val client = server.accept()
            handle(client)
        }
    }

    fun listenBacklog(port: Int) {
~>        ServerSocket(port, 50).use { server -> handle(server.accept()) }
    }

    fun listenAny(port: Int) {
~>        val server = ServerSocket(port, 50, InetAddress.getByName("0.0.0.0"))
        handle(server.accept())
    }

    fun listenBound(port: Int) {
        val server = ServerSocket()
        server.reuseAddress = true
~>        server.bind(InetSocketAddress(port))
        handle(server.accept())
    }
}
