package com.acme.agent

import java.net.ServerSocket
import java.net.Socket
import kotlin.test.Test

class CommandListenerTest {
    @Test
    fun `accepts a command`() {
        val server = ServerSocket(9099)
        val client = Socket("ci-runner.internal", 9099)
        client.getOutputStream().write("status\n".toByteArray())
        server.close()
    }
}
