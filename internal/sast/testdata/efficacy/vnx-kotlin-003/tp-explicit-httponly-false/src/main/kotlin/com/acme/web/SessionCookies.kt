package com.acme.web

import javax.servlet.ServletContext
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletResponse

class SessionCookies(private val servletContext: ServletContext) {
    fun issue(response: HttpServletResponse, sessionToken: String) {
        val cookie = Cookie("auth_token", sessionToken)
~>        cookie.setHttpOnly(false)
        cookie.secure = true
        response.addCookie(cookie)
    }

    fun issueReadable(response: HttpServletResponse, sid: String) {
        val cookie = Cookie("sid", sid)
~>        cookie.isHttpOnly = false
        response.addCookie(cookie)
    }

    fun issueApply(response: HttpServletResponse, userId: String) {
        response.addCookie(Cookie("user_session", userId).apply {
~>            isHttpOnly = false
            secure = true
        })
    }

    fun configure() {
~>        servletContext.sessionCookieConfig.isHttpOnly = false
    }
}
