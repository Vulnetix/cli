package com.acme.keys

import java.security.KeyPair
import java.security.KeyPairGenerator

object Limits {
    const val RSA_BITS = 1024
}

class KeyService {
    private val generator by lazy { KeyPairGenerator.getInstance("RSA") }
    private val pss: KeyPairGenerator = KeyPairGenerator.getInstance("RSASSA-PSS")

    fun lazyKey(): KeyPair {
~>        generator.initialize(1024)
        return generator.generateKeyPair()
    }

    fun pssKey(): KeyPair = with(pss) {
~>        initialize(Limits.RSA_BITS)
        generateKeyPair()
    }

    fun applied(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.apply {
~>            initialize(512)
        }
        return kpg.generateKeyPair()
    }
}
