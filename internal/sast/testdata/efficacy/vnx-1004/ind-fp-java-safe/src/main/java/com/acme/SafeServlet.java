package com.acme;

import jakarta.servlet.http.*;

public class SafeServlet {
    void ok(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("access_token", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
        Cookie pref = new Cookie("theme", "dark");
        response.addCookie(pref);
    }
}
