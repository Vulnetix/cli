package com.acme.crypto

import java.security.MessageDigest

class PasswordHasher {
    fun hash(password: String): ByteArray {
~>        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray())
    }

    fun sign(data: ByteArray): ByteArray =
~>        MessageDigest.getInstance("SHA-1").digest(data)

    fun legacy(data: ByteArray): ByteArray {
~>        val sha = MessageDigest.getInstance("SHA1", "BC")
~>        val alias = java.security.MessageDigest.getInstance("SHA")
~>        val lower = MessageDigest.getInstance( "md5" )
        return sha.digest(data) + alias.digest(data) + lower.digest(data)
    }

    fun wrapped(data: ByteArray): ByteArray {
~>        val md = MessageDigest.getInstance(
            "MD5",
        )
        return md.digest(data)
    }
}
