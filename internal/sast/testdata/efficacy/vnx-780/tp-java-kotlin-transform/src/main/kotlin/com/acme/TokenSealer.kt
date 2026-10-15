package com.acme

import java.security.PublicKey
import javax.crypto.Cipher

class TokenSealer(private val key: PublicKey) {
    fun seal(token: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(token)
    }

    fun legacy(token: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance(
            "rsa/ecb/pkcs1padding"
        )
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(token)
    }
}
