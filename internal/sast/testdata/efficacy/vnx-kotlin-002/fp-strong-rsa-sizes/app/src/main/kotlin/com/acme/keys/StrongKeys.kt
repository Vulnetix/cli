package com.acme.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.RSAKeyGenParameterSpec

private const val KEY_BITS = 3072

class StrongKeys {
    fun standard() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        kpg.generateKeyPair()
    }

    fun longLived() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(4096, SecureRandom())
        kpg.initialize(KEY_BITS)
        kpg.initialize(RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4))
    }

    fun scoped() = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    fun keystore(alias: String) {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setKeySize(2048)
            .build()
        kpg.initialize(spec)
    }
}
