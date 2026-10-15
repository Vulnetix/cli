package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet {
    public void home(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect(request.getContextPath() + "/login");
        String id = request.getParameter("id");
        response.sendRedirect("/orders/" + id);
    }
}
