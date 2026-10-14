package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Hints {
    // response.sendRedirect(request.getParameter("next")) is an open redirect.
    private static final String HINT = "never return \"redirect:\" + request.getParameter(\"url\")";

    public void home(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        response.getWriter().println(HINT + name);
        response.sendRedirect("/home");
    }
}
