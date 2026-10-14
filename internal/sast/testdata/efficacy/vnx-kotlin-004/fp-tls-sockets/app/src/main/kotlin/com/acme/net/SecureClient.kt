package com.acme.net

import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class SecureClient(private val host: String) {
    fun connect(): SSLSocket {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val socket = factory.createSocket(host, 443) as SSLSocket
        socket.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
        socket.startHandshake()
        return socket
    }

    fun serve() {
        val server = SSLServerSocketFactory.getDefault().createServerSocket(9443)
        server.accept()
    }
}
