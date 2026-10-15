package com.acme.dev

import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket

private const val BRIDGE_HOST = "127.0.0.1"
private const val BRIDGE_PORT = 8700

/**
 * Talks to the local debug daemon. The daemon only ever listens on the
 * loopback interface, so nothing here leaves the machine.
 *
 * The protocol is line based:
 *   HELLO <version>
 *   EVAL <expr>
 *   BYE
 */
class DebugBridge {
    private var lastReply: String? = null

    fun version(): String = "1.4"

    fun hello(): String {
        val line = "HELLO ${version()}"
        return line
    }

    fun connect(): Socket {
        return Socket(BRIDGE_HOST, BRIDGE_PORT)
    }

    fun listen(): ServerSocket {
        val loop = InetAddress.getByName(BRIDGE_HOST)
        return ServerSocket(BRIDGE_PORT, 1, loop)
    }
}
