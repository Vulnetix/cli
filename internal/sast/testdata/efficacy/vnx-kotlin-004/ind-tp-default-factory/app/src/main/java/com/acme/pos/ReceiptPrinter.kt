package com.acme.pos

import javax.net.SocketFactory

class ReceiptPrinter(private val printerHost: String) {
    fun print(receipt: ByteArray) {
~>        val socket = SocketFactory.getDefault().createSocket(printerHost, 9100)
        socket.getOutputStream().use { it.write(receipt) }
        socket.close()
    }
}
