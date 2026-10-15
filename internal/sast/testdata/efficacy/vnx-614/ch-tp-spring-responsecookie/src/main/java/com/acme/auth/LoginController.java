package com.acme.auth;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

public class LoginController {
    public ResponseEntity<Void> login(String jwt) {
~>        ResponseCookie cookie = ResponseCookie.from("AUTH_TOKEN", jwt)
                .httpOnly(true)
                .path("/")
                .maxAge(3600)
                .build();
~>        ResponseCookie refresh = ResponseCookie.from("refresh_token", jwt).secure(false).build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .header(HttpHeaders.SET_COOKIE, refresh.toString())
                .build();
    }
}
