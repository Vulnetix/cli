package com.acme.web;

import javax.servlet.http.*;

public class PrefServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        Cookie lang = new Cookie("language", "en");
        Cookie sess = new Cookie("auth_token", tokens.issue(req));
        // never put new Cookie("role", x) here
        req.getSession().setAttribute("role", "user");
        resp.addCookie(lang);
        resp.addCookie(sess);
    }
}
