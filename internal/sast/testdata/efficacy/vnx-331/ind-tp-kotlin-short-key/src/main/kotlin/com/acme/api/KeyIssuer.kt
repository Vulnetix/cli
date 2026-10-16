package com.acme.api

import java.security.SecureRandom
import java.util.Base64

class KeyIssuer {
    private val rng = SecureRandom()

    fun issue(): String {
~>        val apiKey = ByteArray(6)
        rng.nextBytes(apiKey)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(apiKey)
    }
}
