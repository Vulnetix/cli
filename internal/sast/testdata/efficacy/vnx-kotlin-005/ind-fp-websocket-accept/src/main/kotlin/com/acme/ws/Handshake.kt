package com.acme.ws

import java.security.MessageDigest
import java.util.Base64

private const val WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

fun secWebSocketAccept(secWebSocketKey: String): String {
    val sha1 = MessageDigest.getInstance("SHA-1")
    val digest = sha1.digest((secWebSocketKey.trim() + WEBSOCKET_GUID).toByteArray(Charsets.US_ASCII))
    return Base64.getEncoder().encodeToString(digest)
}
