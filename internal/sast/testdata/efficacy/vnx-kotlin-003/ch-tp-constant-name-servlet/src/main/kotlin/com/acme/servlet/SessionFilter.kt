package com.acme.servlet

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

private const val COOKIE_NAME = "connect.sid"

class SessionFilter {
    fun attach(response: HttpServletResponse, sessionId: String) {
        val cookie = Cookie(COOKIE_NAME, sessionId)
        cookie.maxAge = 60 * 60
        cookie.path = "/"
        cookie.secure = true
~>        response.addCookie(cookie)
    }

    fun rememberMe(response: HttpServletResponse, series: String) {
        Cookie("remember-me", series).also { c ->
            c.maxAge = 14 * 24 * 3600
~>            response.addCookie(c)
        }
    }
}
