package com.acme.keys

import java.security.KeyPairGenerator
import java.security.spec.RSAKeyGenParameterSpec

fun specPair() {
    val kpg = KeyPairGenerator.getInstance("RSA")
~>    kpg.initialize(RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4))
    kpg.generateKeyPair()
}

fun specValue() {
~>    val spec = java.security.spec.RSAKeyGenParameterSpec(768, RSAKeyGenParameterSpec.F0)
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(spec)
}
