package com.acme;

import javax.servlet.http.HttpServlet;

public class HitServletTest extends HttpServlet {
    private static int hits = 0;
    protected void doGet() { hits++; }
}
