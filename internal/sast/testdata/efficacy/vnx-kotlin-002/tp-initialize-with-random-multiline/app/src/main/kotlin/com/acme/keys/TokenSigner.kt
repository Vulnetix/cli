package com.acme.keys

import java.security.KeyPairGenerator
import java.security.SecureRandom

object TokenSigner {
    private val random = SecureRandom()

    fun newPair() = run {
        val rsa = KeyPairGenerator.getInstance("RSA")
~>        rsa.initialize(1024, random)
        rsa.generateKeyPair()
    }

    fun otherPair() = run {
        val rsa = KeyPairGenerator.getInstance("RSA")
~>        rsa.initialize(
            768,
            SecureRandom(),
        )
        rsa.generateKeyPair()
    }
}
