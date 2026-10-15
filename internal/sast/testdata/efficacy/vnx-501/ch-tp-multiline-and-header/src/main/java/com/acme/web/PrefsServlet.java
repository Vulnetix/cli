package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class PrefsServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        HttpSession sess = req.getSession(true);
~>        sess.setAttribute("returnUrl",
                req.getParameter("returnUrl"));
        String ua = req.getHeader("User-Agent");
~>        req.getSession().setAttribute("ua", ua);
        resp.sendRedirect("/prefs");
    }
}
