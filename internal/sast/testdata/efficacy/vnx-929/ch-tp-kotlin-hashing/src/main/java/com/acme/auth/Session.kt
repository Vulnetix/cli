package com.acme.auth

import com.google.common.hash.Hashing
import org.apache.commons.codec.digest.DigestUtils

class Session {
    fun sessionId(user: String, secret: String): String =
~>        Hashing.sha1().hashString(user + secret, Charsets.UTF_8).toString()

    fun resetToken(email: String): String {
~>        val token = DigestUtils.sha1Hex("$email:${System.currentTimeMillis()}")
        return token
    }
}
