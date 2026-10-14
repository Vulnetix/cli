package com.acme.web

import jakarta.servlet.http.Cookie
import kotlin.test.Test
import kotlin.test.assertFalse

class CookieParserTest {
    @Test
    fun readsNonHttpOnlySession() {
        val cookie = Cookie("SESSIONID", "abc")
        cookie.isHttpOnly = false
        val response = FakeResponse()
        response.addCookie(cookie)
        assertFalse(response.cookies.single().isHttpOnly)
    }
}
