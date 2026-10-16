package com.acme.licensing

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom

class LicenseKeys(private val random: SecureRandom = SecureRandom()) {

    fun newSigningPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA")
~>        generator.initialize(1024, random)
        return generator.generateKeyPair()
    }
}
