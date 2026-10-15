package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JumpServlet {
    public void jump(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String target = req.getParameter("url");
        resp.setStatus(302);
~>        resp.sendRedirect(target);
    }
}
