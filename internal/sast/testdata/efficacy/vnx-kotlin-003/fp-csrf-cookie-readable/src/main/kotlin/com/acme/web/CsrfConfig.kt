package com.acme.web

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.web.csrf.CookieCsrfTokenRepository

class CsrfConfig {
    // Angular double-submit: the script must read XSRF-TOKEN.
    val repository = CookieCsrfTokenRepository.withHttpOnlyFalse()

    fun issue(response: HttpServletResponse, csrfToken: String) {
        val cookie = Cookie("XSRF-TOKEN", csrfToken).apply {
            isHttpOnly = false
            secure = true
            path = "/"
        }
        response.addCookie(cookie)
    }
}
