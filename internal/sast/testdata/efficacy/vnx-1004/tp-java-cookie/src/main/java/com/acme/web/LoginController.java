package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;

public class LoginController {
    private static final String COOKIE_NAME = "spoof_auth";

    public void login(HttpServletResponse response, String token) {
~>        Cookie cookie = new Cookie("access_token", token);
        cookie.setSecure(true);
        response.addCookie(cookie);
~>        Cookie other = new Cookie(COOKIE_NAME, token);
        response.addCookie(other);
~>        ResponseCookie rc = ResponseCookie.from("SESSION", token)
            .secure(true)
            .path("/")
            .build();
        response.addHeader("Set-Cookie", rc.toString());
    }
}
