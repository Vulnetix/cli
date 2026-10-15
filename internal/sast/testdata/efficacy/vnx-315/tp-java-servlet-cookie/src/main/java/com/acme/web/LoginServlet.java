package com.acme.web;

import javax.servlet.http.*;

public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String password = req.getParameter("password");
~>        Cookie c = new Cookie("password", password);
        resp.addCookie(c);
~>        resp.addHeader("Set-Cookie", ResponseCookie.from("pin", req.getParameter("pin")).build().toString());
    }
}
