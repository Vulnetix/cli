package com.acme.keys

import java.security.SecureRandom

class KeyMaker {
    private val rng = SecureRandom.getInstance("SHA1PRNG").apply {
~>        setSeed(20240101L)
    }

    fun apiKey(): ByteArray {
        val key = ByteArray(32)
        rng.nextBytes(key)
        return key
    }
}
