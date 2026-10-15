package com.acme

import java.security.MessageDigest

fun sessionToken(userId: String): String {
~>    val md = MessageDigest.getInstance("SHA-1")
    return md.digest(userId.toByteArray()).joinToString("") { "%02x".format(it) }
}
