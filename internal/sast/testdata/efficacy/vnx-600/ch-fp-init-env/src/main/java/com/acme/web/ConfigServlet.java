package com.acme.web;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

public class ConfigServlet extends HttpServlet {
    private int poolSize;

    @Override
    public void init() throws ServletException {
        poolSize = Integer.parseInt(getInitParameter("poolSize"));
        int port = Integer.parseInt(System.getenv("PORT"));
    }
}
