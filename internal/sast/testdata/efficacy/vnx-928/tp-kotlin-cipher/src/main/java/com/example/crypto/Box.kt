package com.example.crypto

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

private const val ALGO = "DESede/CBC/PKCS5Padding"

class Box(private val raw: ByteArray) {
    fun seal(data: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance(ALGO)
~>        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(raw, "DES"))
        return cipher.doFinal(data)
    }

    fun rc2(): Cipher =
~>        Cipher.getInstance("RC2/CBC/PKCS5Padding")
}
