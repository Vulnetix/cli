package com.acme

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

object CookieFixtures {
    fun plantSession(response: HttpServletResponse) {
        response.addCookie(Cookie("SESSION", "fixture"))
        Cookie("jwt", "x").apply { isHttpOnly = false }
    }
}
