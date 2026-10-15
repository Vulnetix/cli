package com.acme.net

import java.net.InetSocketAddress
import java.net.Socket

object Connectivity {
    fun isOnline(): Boolean = try {
        Socket().use { it.connect(InetSocketAddress("8.8.8.8", 53), 1500) }
        true
    } catch (e: Exception) {
        false
    }
}
