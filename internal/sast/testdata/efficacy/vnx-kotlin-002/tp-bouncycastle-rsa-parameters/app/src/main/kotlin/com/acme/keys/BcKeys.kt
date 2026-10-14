package com.acme.keys

import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters

fun bcPair() {
    val gen = RSAKeyPairGenerator()
~>    gen.init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), SecureRandom(), 1024, 80))
    gen.generateKeyPair()
}
