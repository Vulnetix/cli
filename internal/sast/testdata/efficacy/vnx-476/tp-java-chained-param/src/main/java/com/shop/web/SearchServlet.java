package com.shop.web;

import java.io.File;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
~>        String q = request.getParameter("q").trim();
~>        if (System.getenv("APP_MODE").equals("debug")) {
            log(q);
        }
~>        int size = System.getProperty("search.size").length();
        File dir = new File("/var/data");
~>        for (File f : dir.listFiles()) {
            log(f.getName());
        }
    }
}
