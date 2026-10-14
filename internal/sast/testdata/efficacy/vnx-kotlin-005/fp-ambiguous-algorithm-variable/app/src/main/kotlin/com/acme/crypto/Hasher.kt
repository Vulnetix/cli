package com.acme.crypto

import java.security.MessageDigest

class Hasher(private val algorithm: String) {
    private var mode = "SHA-256"

    fun configureLegacy() {
        mode = "MD5"
    }

    fun digest(data: ByteArray): ByteArray = MessageDigest.getInstance(algorithm).digest(data)

    fun digestMode(data: ByteArray): ByteArray = MessageDigest.getInstance(mode).digest(data)
}
