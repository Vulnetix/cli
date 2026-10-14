package com.acme.net

import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class SmtpClient(private val host: String, private val ctx: SSLContext) {
    fun open(): SSLSocket {
        val plain = Socket(host, 587)
        plain.getOutputStream().write("EHLO acme.io\r\nSTARTTLS\r\n".toByteArray())
        return ctx.socketFactory.createSocket(plain, host, 587, true) as SSLSocket
    }
}
