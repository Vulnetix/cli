package com.acme

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class TokenSealer(private val key: ByteArray) {
    fun seal(iv: ByteArray, plain: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance("AES/OFB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(plain)
    }
}
