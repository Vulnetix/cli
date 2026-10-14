package com.acme.net

import java.net.InetSocketAddress
import java.net.Socket

class Uploader(private val config: Config) {
    fun upload(bytes: ByteArray) {
        val s = Socket()
        s.soTimeout = 5000
~>        s.connect(InetSocketAddress(config.host, config.port), 5000)
        s.getOutputStream().write(bytes)
    }
}
