package com.acme.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

class MixedKeys {
    fun ecKey() {
        val ec = KeyPairGenerator.getInstance("EC")
        ec.initialize(256)
        ec.generateKeyPair()
    }

    fun ecNamedCurve() {
        val ec = KeyPairGenerator.getInstance("EC")
        ec.initialize(ECGenParameterSpec("secp384r1"))
    }

    fun aesKey() {
        val aes = KeyGenerator.getInstance("AES")
        aes.init(128)
        aes.generateKey()
    }

    fun keystoreAes(alias: String) {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        keyGenerator.generateKey()
    }

    fun keystoreEc(alias: String) {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setKeySize(256)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build(),
        )
    }

    fun ed() = KeyPairGenerator.getInstance("Ed25519").apply { initialize(255) }.generateKeyPair()

    fun rsaThenEc() {
        val rsa = KeyPairGenerator.getInstance("RSA")
        rsa.initialize(4096)
        val ec = KeyPairGenerator.getInstance("EC")
        ec.initialize(521)
    }
}

class LazyEc {
    private val ecGen by lazy { KeyPairGenerator.getInstance("EC") }

    fun key() = with(ecGen) {
        initialize(384)
        generateKeyPair()
    }

    fun other() {
        ecGen.initialize(256)
    }
}
