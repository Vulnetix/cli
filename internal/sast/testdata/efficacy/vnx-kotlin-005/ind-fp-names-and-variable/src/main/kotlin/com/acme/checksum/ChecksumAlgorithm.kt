package com.acme.checksum

import java.security.MessageDigest

enum class ChecksumAlgorithm(val jcaName: String) {
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
}

val DEPRECATED_ALGORITHMS = setOf("MD5", "SHA-1", "MD2")

fun checksum(algorithm: ChecksumAlgorithm, bytes: ByteArray): ByteArray =
    MessageDigest.getInstance(algorithm.jcaName).digest(bytes)

fun rejectWeak(name: String) {
    require(name !in DEPRECATED_ALGORITHMS) { "MessageDigest.getInstance(\"MD5\") is not allowed" }
}
