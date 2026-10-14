package com.acme.web

import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity

class TokenEndpoint {
    fun issue(refreshToken: String): ResponseEntity<Unit> {
~>        val cookie = ResponseCookie.from("refresh_token", refreshToken)
            .secure(true)
            .path("/auth")
            .sameSite("Strict")
            .build()
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build()
    }

    fun issueReadable(sessionId: String): ResponseCookie =
        ResponseCookie.from("SESSION", sessionId)
~>            .httpOnly(false)
            .secure(true)
            .build()
}
