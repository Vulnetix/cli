package com.acme.auth;

import java.time.Duration;
import org.springframework.http.ResponseCookie;

public class TokenCookies {
    public ResponseCookie jwtCookie(String token) {
~>        return ResponseCookie.from("jwt", token)
            .httpOnly(true)
            .secure(true)
            .maxAge(Duration.ofDays(90))
            .build();
    }
}
