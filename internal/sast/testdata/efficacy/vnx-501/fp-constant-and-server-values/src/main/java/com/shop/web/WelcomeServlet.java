package com.shop.web;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class WelcomeServlet extends HttpServlet {
    private static final String WELCOMED = "welcomed";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String nonce = UUID.randomUUID().toString();
        session.setAttribute(WELCOMED, "true");
        session.setAttribute("nonce", nonce);
        session.setAttribute("visits", 1);
        response.getWriter().println("hello");
    }
}
