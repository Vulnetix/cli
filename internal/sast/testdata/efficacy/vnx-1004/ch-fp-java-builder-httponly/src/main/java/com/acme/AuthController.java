package com.acme;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;

public class AuthController {
    public String refresh(String token) {
        ResponseCookie cookie = ResponseCookie.from("refresh_token", token)
                .httpOnly(true)
                .secure(true)
                .build();
        return cookie.toString();
    }

    public void login(HttpServletResponse response, String sid) {
        Cookie c = new Cookie("SESSION", sid);
        c.setSecure(true);
        c.setPath("/");
        c.setHttpOnly(true);
        response.addCookie(c);
    }
}
