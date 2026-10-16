package com.acme;

public class TokenEndpoint {
    public void issue(HttpServletResponse response, String token) {
        // Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
        Cookie cookie = new Cookie("access_token", token);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
