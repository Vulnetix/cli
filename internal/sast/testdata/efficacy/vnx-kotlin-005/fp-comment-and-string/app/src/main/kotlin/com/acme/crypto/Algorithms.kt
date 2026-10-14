package com.acme.crypto

import java.security.MessageDigest

/**
 * Migration note: MessageDigest.getInstance("MD5") and DigestUtils.md5Hex(x)
 * were replaced by SHA-256 in 4.0.
 */
enum class Algorithm(val jcaName: String) {
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
}

data class Artifact(val md5: String?, val sha1: String?, val sha256: String)

class Algorithms {
    // val md = MessageDigest.getInstance("SHA-1")
    fun describe(): String = "Do not call MessageDigest.getInstance(\"MD5\") or Hashing.md5()"

    fun supported(): List<String> = listOf("MD5", "SHA-1", "SHA-256")

    fun preferred(): MessageDigest = MessageDigest.getInstance(Algorithm.SHA256.jcaName)
}
