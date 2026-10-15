package com.acme.web;

import javax.servlet.http.Cookie;

public class PrefServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        resp.addCookie(new Cookie("JSESSIONID", req.getSession().getId()));
        resp.addCookie(new Cookie("locale", "en"));
        for (Cookie c : req.getCookies()) {
            if (c.getName().equals("tracking")) {
                log(c.getValue());
            }
        }
        String role = (String) req.getSession().getAttribute("role");
        if ("admin".equals(role)) {
            resp.addCookie(new Cookie("lastAdminView", now()));
        }
    }
}
