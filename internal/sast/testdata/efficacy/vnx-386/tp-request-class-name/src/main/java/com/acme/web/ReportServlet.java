package com.acme.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String renderer = request.getParameter("renderer");
        try {
~>            Object r = Class.forName(renderer).getDeclaredConstructor().newInstance();
            response.getWriter().print(r);
        } catch (ReflectiveOperationException e) {
            response.sendError(400);
        }
    }

    protected Object fromHeader(HttpServletRequest req) throws Exception {
        String type = req.getHeader("X-Handler");
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
~>        return loader.loadClass(type).getDeclaredConstructor().newInstance();
    }
}
