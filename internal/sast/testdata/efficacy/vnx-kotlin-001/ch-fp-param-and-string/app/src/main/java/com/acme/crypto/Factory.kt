package com.acme.crypto

import javax.crypto.Cipher

class Factory(private val transformation: String = "AES/GCM/NoPadding") {
    fun create(): Cipher = Cipher.getInstance(transformation)

    // Never pass "AES/ECB/PKCS5Padding" here.
    val help = "ECB mode leaks patterns; use Cipher.getInstance(\"AES/GCM/NoPadding\")"
}
