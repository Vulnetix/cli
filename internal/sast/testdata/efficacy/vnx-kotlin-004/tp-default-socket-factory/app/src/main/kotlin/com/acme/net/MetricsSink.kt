package com.acme.net

import javax.net.SocketFactory

class MetricsSink(private val endpoint: String) {
    fun push(line: String) {
~>        val socket = SocketFactory.getDefault().createSocket(endpoint, 2003)
        socket.getOutputStream().write("$line\n".toByteArray())
        socket.close()
    }
}
