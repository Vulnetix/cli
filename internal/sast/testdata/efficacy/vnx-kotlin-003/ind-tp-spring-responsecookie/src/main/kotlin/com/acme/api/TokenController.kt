package com.acme.api

import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.time.Duration

@RestController
class TokenController(private val tokens: TokenService) {

    @PostMapping("/auth/token")
    fun issue(@RequestBody creds: Credentials): ResponseEntity<TokenResponse> {
        val pair = tokens.issue(creds)
~>        val refresh = ResponseCookie.from("refresh_token", pair.refreshToken)
            .secure(true)
            .path("/auth")
            .sameSite("Strict")
            .maxAge(Duration.ofDays(14))
            .build()
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, refresh.toString())
            .body(TokenResponse(pair.accessToken))
    }
}
