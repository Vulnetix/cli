package com.acme.legacy

import java.security.KeyPair
import java.security.KeyPairGenerator

class DsaSigner {
    companion object {
        private const val DSA_KEY_BITS = 1024
    }

    fun generate(): KeyPair =
        KeyPairGenerator.getInstance("DSA").apply {
~>            initialize(DSA_KEY_BITS)
        }.generateKeyPair()
}
