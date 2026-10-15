package com.example.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet {
    void issue(HttpServletResponse response, String sid, String name) {
        Cookie session = new Cookie("JSESSIONID", sid);
        session.setHttpOnly(true);
        session.setSecure(true);
        response.addCookie(session);

        Cookie theme = new Cookie("theme", "dark");
        response.addCookie(theme);

        Cookie c = new Cookie(name, sid);
        c.setSecure(request.isSecure());
        response.addCookie(c);
    }
}
