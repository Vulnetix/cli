package com.acme.net

import java.io.PrintWriter
import java.net.Socket

class TelemetryClient(private val host: String, private val port: Int) {
    fun send(userId: String, payload: String) {
~>        val socket = Socket(host, port)
        PrintWriter(socket.getOutputStream(), true).use { it.println("$userId:$payload") }
        socket.close()
    }

    fun ping() {
~>        Socket("telemetry.acme.io", 7000).use { s ->
            s.getOutputStream().write("PING\n".toByteArray())
        }
    }

    fun legacy(password: String) {
~>        val conn = java.net.Socket(
            "auth.acme.io",
            2323,
        )
        conn.outputStream.write(password.toByteArray())
    }
}
