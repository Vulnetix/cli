package org.acme.sign

import java.security.KeyPairGenerator

class Signer {
    private lateinit var kpg: KeyPairGenerator

    init {
        kpg = KeyPairGenerator.getInstance("DSA")
    }

    fun rotate() {
~>        kpg.initialize(1024)
        val pair = kpg.generateKeyPair()
        store(pair.public.encoded)
    }

    private fun store(bytes: ByteArray) = Unit
}
