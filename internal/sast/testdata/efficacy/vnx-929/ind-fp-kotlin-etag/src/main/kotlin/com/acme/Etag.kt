package com.acme

import java.security.MessageDigest

class Etag {
    fun etagFor(body: ByteArray): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(body).joinToString("") { "%02x".format(it) }
    }
}
