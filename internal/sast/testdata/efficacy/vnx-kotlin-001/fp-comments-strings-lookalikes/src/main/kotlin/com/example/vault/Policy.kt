package com.example.vault

import javax.crypto.Cipher

object Policy {
    // Cipher.getInstance("AES/ECB/PKCS5Padding") leaks block patterns.
    /* Cipher.getInstance("AES") defaults to ECB on most providers. */
    val forbidden = setOf("AES/ECB/PKCS5Padding", "DESede/ECB/NoPadding")
    const val ecbWarning = "ECB mode is not allowed"

    fun check(transformation: String) {
        require(transformation !in forbidden) { "Cipher.getInstance(\"AES/ECB\") is forbidden" }
        println("ECB checked for $transformation")
    }

    fun create(): Cipher = Cipher.getInstance("AES/GCM/NoPadding") // not ECB
}
