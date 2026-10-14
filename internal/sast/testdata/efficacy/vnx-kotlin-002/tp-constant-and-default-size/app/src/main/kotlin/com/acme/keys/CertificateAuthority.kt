package com.acme.keys

import java.security.KeyPair
import java.security.KeyPairGenerator

private const val RSA_KEY_BITS = 1024

class CertificateAuthority {
    fun issuerKey(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
~>        kpg.initialize(RSA_KEY_BITS)
        return kpg.generateKeyPair()
    }

    fun leafKey(bits: Int = 1024): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
~>        kpg.initialize(bits)
        return kpg.generateKeyPair()
    }
}
