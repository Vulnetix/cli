package com.acme.legacy

import javax.crypto.Cipher

object Codec {
~>    fun des(): Cipher = Cipher.getInstance("DES")
~>    fun tea(): Cipher = Cipher.getInstance("Twofish/ECB/NoPadding")
    fun ok(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
}
