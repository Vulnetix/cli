package com.acme.auth

import java.security.MessageDigest

class ApiTokenHasher {
    fun hash(token: String): String {
~>        val md = MessageDigest.getInstance("MD5")
        return md.digest(token.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    fun legacyFingerprint(bytes: ByteArray): ByteArray =
~>        MessageDigest.getInstance("sha1", "BC").digest(bytes)
}
