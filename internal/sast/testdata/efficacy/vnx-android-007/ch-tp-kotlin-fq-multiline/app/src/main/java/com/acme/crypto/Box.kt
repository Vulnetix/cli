package com.acme.crypto

import javax.crypto.spec.SecretKeySpec

object Box {
    fun seal(key: ByteArray, plain: ByteArray): ByteArray {
~>        val cipher = javax.crypto.Cipher.getInstance(
            "AES"
        )
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(plain)
    }
}
