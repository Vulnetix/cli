package com.example.vault

import javax.crypto.Cipher

object LegacyCrypto {
~>    fun aes(): Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")

~>    fun tripleDes(): Cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding", "BC")

~>    fun blowfish(): Cipher = javax.crypto.Cipher.getInstance( "Blowfish/ECB/NoPadding" )

    fun sm4(): Cipher {
~>        val c = Cipher.getInstance(
            "SM4/ECB/PKCS7Padding"
        )
        return c
    }
}
