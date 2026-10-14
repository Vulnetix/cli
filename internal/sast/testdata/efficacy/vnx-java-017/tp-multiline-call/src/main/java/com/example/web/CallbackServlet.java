package com.example.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CallbackServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse servletResponse) throws IOException {
        String state  =  request.getParameter( "state" );
~>        servletResponse.setHeader(
            "X-OAuth-State",
            state);
~>        servletResponse . sendRedirect(
            request.getPathInfo());
    }
}
