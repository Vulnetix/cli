package com.acme.telemetry

import java.net.InetSocketAddress
import java.net.Socket

class Uplink(private val collector: String) {
    fun send(payload: String) {
        Socket().use {
~>            it.connect(InetSocketAddress(collector, 5140), 3_000)
            it.getOutputStream().bufferedWriter().apply {
                write(payload)
                flush()
            }
        }
    }
}
