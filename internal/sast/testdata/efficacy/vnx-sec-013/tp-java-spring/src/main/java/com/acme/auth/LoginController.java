package com.acme.auth;

public class LoginController {
    public void login(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("SESSION", token);
~>        cookie.setHttpOnly(false);
        // Reported by VNX-614 (a cookie without Secure), not by this rule.
        cookie.setSecure(false);
        response.addCookie(cookie);
    }
}
