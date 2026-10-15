package com.shop.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class PrefsServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
~>        session.setAttribute("theme", request.getParameter("theme"));
~>        request.getSession(true).putValue("locale", request.getHeader("Accept-Language"));
        response.sendRedirect("/prefs");
    }
}
