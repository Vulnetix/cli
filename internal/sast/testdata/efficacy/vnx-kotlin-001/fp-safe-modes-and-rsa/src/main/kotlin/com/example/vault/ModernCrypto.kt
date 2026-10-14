package com.example.vault

import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class ModernCrypto {
    fun gcm(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    fun cbc(): Cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    fun ctr(): Cipher = Cipher.getInstance("$ALGORITHM/CTR/NoPadding")
    fun rsaOaep(): Cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    fun rsaKeystore(): Cipher = Cipher.getInstance(RSA_TRANSFORMATION)
    fun chacha(): Cipher = Cipher.getInstance("ChaCha20-Poly1305")
    fun keystore(): Cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/${KeyProperties.ENCRYPTION_PADDING_NONE}")
    fun keyGen(): KeyGenerator = KeyGenerator.getInstance("AES")
    fun spec(raw: ByteArray) = SecretKeySpec(raw, ALGORITHM)
    fun mac(): Mac = Mac.getInstance("HmacSHA256")

    companion object {
        private const val ALGORITHM = "AES"
        private const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    }
}
