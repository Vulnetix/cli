package com.acme.auth

import org.springframework.http.ResponseCookie
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse

class LoginHandler(private val tokens: TokenService) {
    suspend fun login(req: ServerRequest): ServerResponse {
        val jwt = tokens.issue(req)
~>        val cookie = ResponseCookie
            .from("access_token", jwt)
            .path("/")
            .secure(true)
            .sameSite("Strict")
            .build()
        return ServerResponse.ok().cookie(cookie).buildAndAwait()
    }
}
