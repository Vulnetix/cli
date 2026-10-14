package com.acme.crypto

import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals

class ChecksumTest {
    @Test
    fun matchesKnownMd5Vector() {
        val md = MessageDigest.getInstance("MD5")
        val hex = md.digest("abc".toByteArray()).joinToString("") { "%02x".format(it) }
        assertEquals("900150983cd24fb0d6963f7d28e17f72", hex)
    }
}
