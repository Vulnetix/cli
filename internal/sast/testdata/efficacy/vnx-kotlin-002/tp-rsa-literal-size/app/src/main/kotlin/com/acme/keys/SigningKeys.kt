package com.acme.keys

import java.security.KeyPair
import java.security.KeyPairGenerator

class SigningKeys {
    fun legacyDeviceKey(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
~>        kpg.initialize(1024)
        return kpg.generateKeyPair()
    }

    fun tinyKey(): KeyPair {
        val generator: KeyPairGenerator = KeyPairGenerator.getInstance("rsa", "BC")
~>        generator.initialize( 512 )
        return generator.genKeyPair()
    }
}
