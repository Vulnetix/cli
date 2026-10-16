package com.acme.session

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.RSAKeyGenParameterSpec

class HandshakeKeys {
    private val rsaGenerator by lazy { KeyPairGenerator.getInstance("RSA") }

    fun ephemeral(): KeyPair {
~>        rsaGenerator.initialize(RSAKeyGenParameterSpec(768, RSAKeyGenParameterSpec.F4))
        return rsaGenerator.generateKeyPair()
    }
}
