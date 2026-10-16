package com.acme.notes.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object VaultKey {
    // Previously: kpg.initialize(1024) with an RSA wrapping key; replaced by AES-GCM.
    fun create(alias: String): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        Log.d("VaultKey", "do not call kpg.initialize(1024) here")
        return keyGenerator.generateKey()
    }
}
