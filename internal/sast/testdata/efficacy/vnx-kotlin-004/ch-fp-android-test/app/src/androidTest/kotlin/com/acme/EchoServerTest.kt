package com.acme

import java.net.ServerSocket
import java.net.Socket

class EchoServerTest {
    fun roundTrip() {
        val server = ServerSocket(0)
        val client = Socket("10.1.2.3", server.localPort)
        client.close()
    }
}
