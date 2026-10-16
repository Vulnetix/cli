package com.acme.web

import jakarta.servlet.http.Cookie
import org.springframework.mock.web.MockHttpServletResponse
import kotlin.test.Test
import kotlin.test.assertEquals

class LoginServletTest {
    @Test
    fun `echoes the session cookie`() {
        val response = MockHttpServletResponse()
        response.addCookie(Cookie("SESSIONID", "abc123"))
        assertEquals("abc123", response.getCookie("SESSIONID")?.value)
    }
}
