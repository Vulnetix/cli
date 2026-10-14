package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (authenticate(request)) {
            String next = request.getParameter("next");
~>            response.sendRedirect(next);
            return;
        }
~>        response.sendRedirect(request.getHeader("Referer"));
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
~>        resp.sendRedirect(
                req.getParameter("returnTo"));
    }

    private boolean authenticate(HttpServletRequest request) {
        return request.getUserPrincipal() != null;
    }
}
