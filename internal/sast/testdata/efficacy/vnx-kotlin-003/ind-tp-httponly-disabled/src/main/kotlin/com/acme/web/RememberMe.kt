package com.acme.web

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.session.web.http.DefaultCookieSerializer

class RememberMe(private val tokens: RememberTokens) {
    fun remember(response: HttpServletResponse, userId: Long) {
        val cookie = Cookie("remember_me", tokens.mint(userId)).apply {
            secure = true
~>            isHttpOnly = false
            maxAge = 60 * 60 * 24 * 30
        }
        response.addCookie(cookie)
    }
}

fun cookieSerializer(): DefaultCookieSerializer {
    val serializer = DefaultCookieSerializer()
    serializer.setCookieName("SESSION")
~>    serializer.setUseHttpOnlyCookie(false)
    return serializer
}
