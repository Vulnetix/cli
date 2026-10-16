package com.acme.mail

import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class SmtpClient(private val host: String) {
    fun connect(): SSLSocket {
        val plain = Socket(host, 587)
        val writer = plain.getOutputStream().bufferedWriter()
        writer.write("EHLO acme.example\r\nSTARTTLS\r\n")
        writer.flush()
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val tls = factory.createSocket(plain, host, 587, true) as SSLSocket
        tls.startHandshake()
        return tls
    }
}
