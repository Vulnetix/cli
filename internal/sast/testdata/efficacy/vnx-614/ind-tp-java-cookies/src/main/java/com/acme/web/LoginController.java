package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private final TokenService tokens;

    public LoginController(TokenService tokens) {
        this.tokens = tokens;
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(HttpServletResponse response, String user) {
        String sessionId = tokens.newSession(user);
~>        Cookie session = new Cookie("JSESSIONID", sessionId);
        session.setHttpOnly(true);
        session.setPath("/");
        response.addCookie(session);

        String jwt = tokens.jwt(user);
~>        ResponseCookie auth = ResponseCookie.from("AUTH_TOKEN", jwt).httpOnly(true).path("/").build();
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, auth.toString()).build();
    }
}
