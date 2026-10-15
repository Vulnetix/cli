package com.acme;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

public class AuthController {
    public ResponseEntity<Void> refresh(String token) {
~>        ResponseCookie cookie = ResponseCookie.from("refresh_token", token)
                .secure(true)
                .path("/")
                .build();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
    }

    public void login(HttpServletResponse response, String sid) {
~>        Cookie c = new Cookie("JSESSIONID", sid);
        c.setSecure(true);
        c.setPath("/");
        response.addCookie(c);
    }
}
