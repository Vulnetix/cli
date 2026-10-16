package com.acme.crypto

import java.security.KeyPair
import java.security.KeyPairGenerator

class GenericKeys(private val algorithm: String) {
    fun generate(bits: Int = 1024): KeyPair {
        val kpg = KeyPairGenerator.getInstance(algorithm)
        kpg.initialize(bits)
        return kpg.generateKeyPair()
    }
}
