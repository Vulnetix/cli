package com.acme;

public class TokenEndpoint {
    public void issue(HttpServletResponse response, String token) {
~>        Cookie cookie = new Cookie("access_token", token);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
