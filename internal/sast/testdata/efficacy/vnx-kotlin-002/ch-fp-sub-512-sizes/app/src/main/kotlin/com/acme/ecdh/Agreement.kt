package com.acme.ecdh

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class Agreement {
    fun ecKey() {
        val rsaFallback = KeyPairGenerator.getInstance("RSA")
        rsaFallback.initialize(4096)
        val spec = KeyGenParameterSpec.Builder("agree", KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp384r1"))
            .setKeySize(384)
            .build()
        val ec = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        ec.initialize(spec)
    }
}
