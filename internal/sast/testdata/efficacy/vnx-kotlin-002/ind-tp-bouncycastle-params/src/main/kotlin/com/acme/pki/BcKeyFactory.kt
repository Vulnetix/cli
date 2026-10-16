package com.acme.pki

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import java.math.BigInteger
import java.security.SecureRandom

fun generateDeviceCertKey(): AsymmetricCipherKeyPair {
    val generator = RSAKeyPairGenerator()
~>    generator.init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), SecureRandom(), 1024, 80))
    return generator.generateKeyPair()
}
