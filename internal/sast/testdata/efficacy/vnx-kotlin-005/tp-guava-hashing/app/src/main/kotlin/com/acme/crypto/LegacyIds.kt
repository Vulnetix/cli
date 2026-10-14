package com.acme.crypto

import com.google.common.hash.Hashing
import java.nio.charset.StandardCharsets

class LegacyIds {
    fun integrity(body: String): String =
~>        Hashing.md5().hashString(body, StandardCharsets.UTF_8).toString()

    @Suppress("DEPRECATION")
    fun signature(body: ByteArray): String =
~>        Hashing.sha1().hashBytes(body).toString()
}
