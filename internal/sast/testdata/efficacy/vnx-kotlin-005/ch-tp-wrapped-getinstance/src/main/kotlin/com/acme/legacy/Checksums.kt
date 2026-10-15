package com.acme.legacy

import java.security.MessageDigest

object Checksums {
    fun fingerprint(data: ByteArray): ByteArray {
        val md = MessageDigest
~>            .getInstance("SHA-1")
        return md.digest(data)
    }

    fun md5(data: ByteArray): ByteArray =
~>        java.security.MessageDigest.getInstance(
            "MD5",
        ).digest(data)
}
