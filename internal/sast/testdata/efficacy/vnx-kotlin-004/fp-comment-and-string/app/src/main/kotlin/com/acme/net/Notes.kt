package com.acme.net

/**
 * The old client used `val socket = Socket(host, port)` and sent the token
 * in cleartext; ServerSocket(9090) was removed as well.
 */
class Notes {
    fun describe(host: String): String {
        // val s = Socket(host, 23)
        return "connect with Socket(host, port) only behind TLS: $host"
    }
}
