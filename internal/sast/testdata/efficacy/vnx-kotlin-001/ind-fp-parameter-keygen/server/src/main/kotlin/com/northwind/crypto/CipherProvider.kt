package com.northwind.crypto

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class CipherProvider(private val transformation: String) {

    fun newKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    fun fromBytes(raw: ByteArray): SecretKey = SecretKeySpec(raw, "AES")

    fun cipher(): Cipher = Cipher.getInstance(transformation)

    fun cipherFor(mode: String): Cipher {
        require(mode == "GCM" || mode == "CBC") { "unsupported block mode $mode" }
        return Cipher.getInstance("AES/$mode/NoPadding")
    }
}
