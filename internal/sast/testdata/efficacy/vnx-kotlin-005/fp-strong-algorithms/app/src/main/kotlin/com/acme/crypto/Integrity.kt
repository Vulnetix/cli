package com.acme.crypto

import com.google.common.hash.Hashing
import java.security.MessageDigest
import java.security.Signature
import okio.ByteString.Companion.encodeUtf8
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.codec.digest.MessageDigestAlgorithms

private const val HASH_ALGORITHM = "SHA-256"

class Integrity {
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)
    fun sha3(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA3-256").digest(data)
    fun constant(data: ByteArray): ByteArray = MessageDigest.getInstance(HASH_ALGORITHM).digest(data)
    fun commons(data: ByteArray): ByteArray = MessageDigest.getInstance(MessageDigestAlgorithms.SHA_256).digest(data)
    fun hex(password: String): String = DigestUtils.sha256Hex(password)
    fun guava(body: String): String = Hashing.sha256().hashUnencodedChars(body).toString()
    fun sig(): Signature = Signature.getInstance("SHA256withRSA")
    fun okio(password: String): String = password.encodeUtf8().sha256().hex()
}
