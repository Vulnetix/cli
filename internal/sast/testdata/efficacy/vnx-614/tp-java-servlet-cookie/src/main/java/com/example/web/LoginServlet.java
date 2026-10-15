package com.example.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet {
    void issue(HttpServletResponse response, String sid, String pref) {
~>        Cookie session = new Cookie("JSESSIONID", sid);
        session.setHttpOnly(true);
        response.addCookie(session);

        Cookie p = new Cookie("display", pref);
~>        p.setSecure(false);
        response.addCookie(p);

        javax.servlet.http.Cookie remember =
~>                new javax.servlet.http.Cookie("remember_token", sid);
        remember.setMaxAge(3600);
        response.addCookie(remember);
    }
}
