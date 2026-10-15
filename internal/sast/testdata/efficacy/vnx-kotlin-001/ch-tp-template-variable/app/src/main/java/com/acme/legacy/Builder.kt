package com.acme.legacy

import javax.crypto.Cipher

fun buildCipher(): Cipher {
    val algorithm = "DES"
~>    return Cipher.getInstance("$algorithm/ECB/PKCS5Padding")
}
