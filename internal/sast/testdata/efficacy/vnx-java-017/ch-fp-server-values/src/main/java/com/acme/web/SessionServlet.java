package com.acme.web;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SessionServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = request.getParameter("user");
        audit(user);
        response.setHeader("X-Request-Id", UUID.randomUUID().toString());
        response.setHeader("Cache-Control", "no-store");
        long count = Long.parseLong(request.getParameter("count"));
        response.setHeader("X-Count", Long.toString(count));
        // response.setHeader("X-User", user);
        response.sendRedirect(request.getContextPath() + "/home");
    }

    private void audit(String who) {
    }
}
