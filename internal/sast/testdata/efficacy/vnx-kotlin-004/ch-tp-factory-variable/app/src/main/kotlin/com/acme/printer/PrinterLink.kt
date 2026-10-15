package com.acme.printer

import javax.net.SocketFactory

class PrinterLink(private val host: String) {
    private val factory: SocketFactory = SocketFactory.getDefault()

    fun print(job: ByteArray) {
~>        val socket = factory.createSocket(host, 9100)
        socket.getOutputStream().use { it.write(job) }
        socket.close()
    }
}
