package com.acme.auth;

import javax.servlet.http.Cookie;
import org.springframework.http.ResponseCookie;

public class LoginController {
    ResponseCookie issue(String jwt) {
        return ResponseCookie.from("AUTH_TOKEN", jwt)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .build();
    }

    Cookie expire() {
        Cookie gone = new Cookie("JSESSIONID", "");
        gone.setMaxAge(0);
        return gone;
    }
}
