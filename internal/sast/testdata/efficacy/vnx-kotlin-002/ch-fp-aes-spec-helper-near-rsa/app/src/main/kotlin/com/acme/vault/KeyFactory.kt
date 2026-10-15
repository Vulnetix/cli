package com.acme.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import javax.crypto.KeyGenerator

class VaultKeys {
    fun signingKey() {
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        gen.initialize(
            KeyGenParameterSpec.Builder("sign", KeyProperties.PURPOSE_SIGN)
                .setKeySize(3072)
                .setDigests(@@sample:K[e]yP[r]op[e]rt[i]es[.]DI[G]ES[T][_]S[H]A2[5]6@@)
                .build()
        )
        gen.generateKeyPair()
    }

    private fun aesSpec(alias: String) =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

    fun dataKey(alias: String) {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGen.init(aesSpec(alias))
        keyGen.generateKey()
    }
}
