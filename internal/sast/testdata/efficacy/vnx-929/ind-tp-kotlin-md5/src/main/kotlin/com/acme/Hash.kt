package com.acme

import java.security.MessageDigest

fun hashPassword(pw: String): ByteArray {
~>    val md = MessageDigest.getInstance("MD5")
    return md.digest(pw.toByteArray())
}
