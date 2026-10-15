package com.shop.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuditServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // never do: session.setAttribute("x", request.getParameter("x"));
        String msg = "do not call session.setAttribute(name, request.getParameter(name))";
        String page = request.getParameter("page");
        Object user = request.getSession().getAttribute("user");
        response.getWriter().println(msg + page + user);
    }
}
