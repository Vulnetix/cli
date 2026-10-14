package com.acme.net

import java.net.ServerSocket
import java.net.Socket
import kotlin.test.Test

class EchoServerTest {
    @Test
    fun echoes() {
        val server = ServerSocket(0)
        val client = Socket(server.inetAddress, server.localPort)
        client.getOutputStream().write(1)
        server.close()
    }
}
