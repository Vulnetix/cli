package com.acme.auth;

public class LoginController {
    public void login(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("SESSION", token);
~>        cookie.setHttpOnly(false);
~>        cookie.setSecure(false);
        response.addCookie(cookie);
    }
}
