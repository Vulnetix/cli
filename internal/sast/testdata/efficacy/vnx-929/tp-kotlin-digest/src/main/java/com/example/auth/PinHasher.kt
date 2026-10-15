package com.example.auth

import java.security.MessageDigest

private const val PIN_HASH = "MD5"

class PinHasher {
    fun hash(pin: String): ByteArray {
~>        val md = MessageDigest.getInstance(PIN_HASH)
        return md.digest(pin.toByteArray())
    }

~>    fun quick(pin: String) = MessageDigest.getInstance("SHA-1").digest(pin.toByteArray())
}
