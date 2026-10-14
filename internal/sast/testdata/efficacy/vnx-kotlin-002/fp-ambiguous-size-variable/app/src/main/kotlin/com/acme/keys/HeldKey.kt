package com.acme.keys

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom

class HeldKey {
    class Builder {
        private var keyAlgorithm: String = "EC"
        private var keySize: Int = 256

        fun rsa2048() = apply {
            keyAlgorithm = "RSA"
            keySize = 2048
        }

        fun ecdsa256() = apply {
            keyAlgorithm = "EC"
            keySize = 256
        }

        fun generate(): KeyPair =
            KeyPairGenerator.getInstance(keyAlgorithm).run {
                initialize(keySize, SecureRandom())
                genKeyPair()
            }

        fun fromCaller(generator: KeyPairGenerator, bits: Int): KeyPair {
            generator.initialize(bits)
            return generator.generateKeyPair()
        }
    }
}
