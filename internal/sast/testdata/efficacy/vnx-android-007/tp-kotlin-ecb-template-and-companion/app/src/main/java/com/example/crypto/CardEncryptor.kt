package com.example.crypto

import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.SecretKey

class CardEncryptor(private val key: SecretKey) {
    fun encrypt(pan: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(pan)
    }

~>    fun legacy(): Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")

~>    fun platformDefault(): Cipher = Cipher.getInstance("AES")

    fun fromKeyProperties(): Cipher =
~>        Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_ECB}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")

~>    fun templated(): Cipher = Cipher.getInstance("$ALG/ECB/NoPadding")

    companion object {
        private const val TRANSFORMATION = "AES/ECB/NoPadding"
        private const val ALG = "AES"
    }
}
