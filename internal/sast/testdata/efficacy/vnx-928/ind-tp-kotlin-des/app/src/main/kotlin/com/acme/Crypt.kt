package com.acme

import javax.crypto.Cipher

object Crypt {
    fun enc(data: ByteArray): ByteArray {
~>        val c = Cipher.getInstance("DES/CBC/PKCS5Padding")
        return c.doFinal(data)
    }
}
