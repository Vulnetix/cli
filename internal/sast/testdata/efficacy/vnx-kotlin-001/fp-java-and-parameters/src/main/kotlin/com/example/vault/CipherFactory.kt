package com.example.vault

import javax.crypto.Cipher

class CipherFactory(private val config: CryptoConfig) {
    fun create(transformation: String): Cipher = Cipher.getInstance(transformation)
    fun configured(): Cipher = Cipher.getInstance(config.transformation)
    fun fromEnv(): Cipher = Cipher.getInstance(System.getenv("CIPHER") ?: "AES/GCM/NoPadding")
}
