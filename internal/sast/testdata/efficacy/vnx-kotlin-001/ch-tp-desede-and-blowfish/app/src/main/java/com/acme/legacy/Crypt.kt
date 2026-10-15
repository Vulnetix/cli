package com.acme.legacy

import javax.crypto.Cipher

class Crypt {
~>    private val triple = Cipher.getInstance("DESede/ECB/PKCS5Padding")
~>    private val fish = Cipher.getInstance("Blowfish")

    fun enc(b: ByteArray) = triple.doFinal(b)
}
