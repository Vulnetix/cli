package com.acme.web

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.ResponseCookie

class SafeLogin {
    fun servlet(response: HttpServletResponse, sessionToken: String) {
        val sessionCookie = Cookie("SESSIONID", sessionToken).apply {
            isHttpOnly = true
            secure = true
            path = "/"
        }
        response.addCookie(sessionCookie)
    }

    fun servletSetter(response: HttpServletResponse, jwt: String) {
        val authCookie = Cookie("auth_token", jwt)
        authCookie.setSecure(true)
        authCookie.setHttpOnly(true)
        response.addCookie(authCookie)
    }

    fun spring(refreshToken: String): ResponseCookie =
        ResponseCookie.from("refresh_token", refreshToken)
            .httpOnly(true)
            .secure(true)
            .path("/auth")
            .build()
}
