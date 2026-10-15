package com.acme

import java.security.SecureRandom

fun sessionKey(): ByteArray {
~>    val sr = SecureRandom("constant".toByteArray())
    val key = ByteArray(32)
    sr.nextBytes(key)
    return key
}
