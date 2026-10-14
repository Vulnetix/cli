package com.acme.crypto

import java.security.MessageDigest
import java.util.Base64

object Handshake {
    private const val WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    fun secWebSocketAccept(clientKey: String): String {
        val sha1 = MessageDigest.getInstance("SHA-1")
        val digest = sha1.digest((clientKey + WEBSOCKET_GUID).toByteArray())
        return Base64.getEncoder().encodeToString(digest)
    }
}
