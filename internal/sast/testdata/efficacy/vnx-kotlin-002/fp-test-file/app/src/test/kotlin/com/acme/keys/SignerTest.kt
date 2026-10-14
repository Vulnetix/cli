package com.acme.keys

import java.security.KeyPairGenerator
import kotlin.test.Test

class SignerTest {
    @Test
    fun signsWithSmallKeyForSpeed() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(1024)
        val pair = kpg.generateKeyPair()
        check(pair.public != null)
    }
}
