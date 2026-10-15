package net.acme.crypto

import java.security.KeyPairGenerator
import java.security.spec.RSAKeyGenParameterSpec

object Limits {
    const val RSA_BITS = 1024
}

class Keys {
    private val generator by lazy { KeyPairGenerator.getInstance("RSA") }

    fun create() {
~>        generator.initialize(RSAKeyGenParameterSpec(Limits.RSA_BITS, @@sample:R[S]AK[e]yG[e]nP[a]ra[m]et[e]rS[p]ec[.]F4@@))
        generator.generateKeyPair()
    }
}
