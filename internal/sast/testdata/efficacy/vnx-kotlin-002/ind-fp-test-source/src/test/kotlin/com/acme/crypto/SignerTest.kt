package com.acme.crypto

import java.security.KeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertNotNull

class SignerTest {
    @Test
    fun `signs with a small throwaway key for speed`() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(512)
        assertNotNull(Signer(kpg.generateKeyPair()).sign("hello".toByteArray()))
    }
}
