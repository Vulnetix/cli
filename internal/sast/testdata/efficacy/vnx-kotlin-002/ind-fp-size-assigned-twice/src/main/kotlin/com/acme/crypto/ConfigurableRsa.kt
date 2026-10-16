package com.acme.crypto

import java.security.KeyPair
import java.security.KeyPairGenerator

fun configurableRsa(profile: String): KeyPair {
    var keyBits = 4096
    if (profile == "interop-legacy") {
        keyBits = 1024
    }
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(keyBits)
    return kpg.generateKeyPair()
}
