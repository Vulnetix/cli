package com.acme

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class Prefs(private val key: SecretKey) {
    fun seal(data: ByteArray): ByteArray {
~>        val iv = "abcdefghijklmnop".toByteArray()
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        return cipher.doFinal(data)
    }
}
