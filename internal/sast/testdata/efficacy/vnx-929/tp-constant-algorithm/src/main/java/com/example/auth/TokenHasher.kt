package com.example.auth

import java.security.MessageDigest

private const val HASH_ALGORITHM = "SHA-1"

class TokenHasher {
    fun hash(token: ByteArray): ByteArray =
~>        MessageDigest.getInstance(HASH_ALGORITHM).digest(token)
}
