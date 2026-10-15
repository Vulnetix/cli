package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeLoginController {
    public void afterLogin(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String next = request.getParameter("next");
        if (next == null || !next.startsWith("/") || next.startsWith("//")) {
            next = "/";
        }
        response.sendRedirect(next);
    }
}
