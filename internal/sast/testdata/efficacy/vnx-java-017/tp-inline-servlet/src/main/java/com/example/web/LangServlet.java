package com.example.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LangServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        response.setHeader("Content-Language", request.getParameter("lang"));
~>        response.addHeader("X-Echo-Referer", request.getHeader("Referer"));
~>        resp().sendRedirect("/home?from=" + request.getQueryString());
    }

    private HttpServletResponse resp() { return null; }
}
