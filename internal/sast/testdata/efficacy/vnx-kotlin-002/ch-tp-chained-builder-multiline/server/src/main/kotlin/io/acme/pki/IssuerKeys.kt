package io.acme.pki

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom

class IssuerKeys(private val random: SecureRandom) {

    fun intermediate(): KeyPair =
        KeyPairGenerator
            .getInstance("RSA", "BC")
            .run {
~>                initialize(
                    1536,
                    random,
                )
                generateKeyPair()
            }

    fun leaf(): KeyPair {
        val gen = KeyPairGenerator.getInstance("RSA")
~>        gen.initialize(/* legacy HSM limit */ 1024)
        return gen.genKeyPair()
    }
}
