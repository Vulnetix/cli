package com.acme.telemetry

import java.io.PrintWriter
import java.net.Socket

class TelemetryClient(private val host: String, private val port: Int) {
    fun send(deviceId: String, payload: String) {
~>        Socket(host, port).use { socket ->
            PrintWriter(socket.getOutputStream(), true).use { out ->
                out.println("$deviceId|$payload")
            }
        }
    }
}
