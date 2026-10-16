package com.acme.integrity

import com.google.common.hash.Hashing
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

private const val INTEGRITY_ALGORITHM = "SHA-1"

object PayloadDigest {
    fun signatureBase(body: String): String =
~>        Hashing.md5().hashString(body, StandardCharsets.UTF_8).toString()

    fun integrity(bytes: ByteArray): ByteArray {
~>        val digest = MessageDigest.getInstance(INTEGRITY_ALGORITHM)
        return digest.digest(bytes)
    }
}
