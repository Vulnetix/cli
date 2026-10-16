package com.acme

import javax.crypto.Cipher

private const val ALGO = "DESede/ECB/PKCS5Padding"

fun legacy(): Cipher {
~>    return Cipher.getInstance(ALGO)
}
