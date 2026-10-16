package com.acme.device

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

object DeviceKeys {
    fun generate(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
~>        kpg.initialize(ECGenParameterSpec("secp192r1"))
        return kpg.generateKeyPair()
    }
}
