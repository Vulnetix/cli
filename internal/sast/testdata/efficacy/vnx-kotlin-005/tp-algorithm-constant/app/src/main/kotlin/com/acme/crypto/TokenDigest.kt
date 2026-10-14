package com.acme.crypto

import java.security.MessageDigest
import org.apache.commons.codec.digest.MessageDigestAlgorithms

private const val HASH_ALGORITHM = "MD5"

object TokenDigest {
    fun of(token: String): ByteArray {
~>        val md = MessageDigest.getInstance(HASH_ALGORITHM)
        return md.digest(token.toByteArray())
    }

    fun commons(token: String): ByteArray {
~>        val md = MessageDigest.getInstance(MessageDigestAlgorithms.SHA_1)
        return md.digest(token.toByteArray())
    }
}
