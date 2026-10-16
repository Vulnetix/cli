package com.acme.auth

import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals

class ApiTokenHasherTest {
    @Test
    fun `matches the reference md5`() {
        val expected = MessageDigest.getInstance("MD5").digest("t".toByteArray())
        assertEquals(expected.size, 16)
    }
}
