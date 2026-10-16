package io.acme;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

public class LoginController {
    public ResponseEntity<Void> login(String user) {
        String sid = sessions.create(user);
        // Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
        ResponseCookie cookie = ResponseCookie.from("SESSION", sid).httpOnly(false).secure(true).build();
        // Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
        ResponseCookie jwt = ResponseCookie.from("access_token", tokens.issue(user))
            .path("/")
            .maxAge(3600)
            .build();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString(), jwt.toString()).build();
    }
}
