package com.example.vault

import android.security.keystore.KeyProperties
import javax.crypto.Cipher

class BlobSealer {
~>    private val cipher = Cipher.getInstance(TRANSFORMATION)

~>    fun templated(): Cipher = Cipher.getInstance("$ALGORITHM/ECB/PKCS5Padding")

    fun keystore(): Cipher =
~>        Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_ECB}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")

    companion object {
        private const val TRANSFORMATION = "AES/ECB/PKCS5Padding"
        private const val ALGORITHM = "DESede"
    }
}
