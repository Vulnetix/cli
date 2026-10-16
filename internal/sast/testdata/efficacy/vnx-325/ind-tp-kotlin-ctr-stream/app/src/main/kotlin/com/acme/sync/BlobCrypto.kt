package com.acme.sync

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class BlobCrypto(private val keyBytes: ByteArray) {
    private val rng = SecureRandom()

    fun seal(data: ByteArray): ByteArray {
        val iv = ByteArray(16).also { rng.nextBytes(it) }
~>        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
        return iv + cipher.doFinal(data)
    }
}
