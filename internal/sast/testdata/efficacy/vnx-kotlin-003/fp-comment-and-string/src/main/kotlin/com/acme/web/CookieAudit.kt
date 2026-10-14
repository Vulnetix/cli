package com.acme.web

import org.slf4j.LoggerFactory

/**
 * Do not write response.addCookie(Cookie("session", id)) without HttpOnly,
 * and never call cookie.setHttpOnly(false) on a session cookie.
 */
class CookieAudit {
    private val log = LoggerFactory.getLogger(CookieAudit::class.java)

    fun warn() {
        // cookie.isHttpOnly = false  <- removed after the 2024 pentest
        log.warn("cookie.setHttpOnly(false) found on session cookie; response.addCookie(Cookie(\"token\", t))")
    }

    fun parse(header: String): Boolean {
        var httpOnly = false
        val secure = header.contains("Secure")
        if (header.contains("HttpOnly")) httpOnly = true
        return httpOnly && secure
    }
}
