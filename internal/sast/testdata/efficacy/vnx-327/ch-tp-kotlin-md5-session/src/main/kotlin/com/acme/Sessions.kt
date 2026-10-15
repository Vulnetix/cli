package com.acme

import java.security.MessageDigest

object Sessions {
    fun sessionId(user: String, issuedAt: Long): String {
~>        val md = MessageDigest.getInstance("MD5")
        val sessionBytes = md.digest("$user:$issuedAt".toByteArray())
        return sessionBytes.joinToString("") { "%02x".format(it) }
    }
}
