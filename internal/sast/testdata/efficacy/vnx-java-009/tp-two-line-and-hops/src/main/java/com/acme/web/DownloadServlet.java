package com.acme.web;

import java.io.FileReader;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Cookie[] cookies = request.getCookies();
        String param = "none";
        for (Cookie c : cookies) {
            if (c.getName().equals("doc")) {
                param = java.net.URLDecoder.decode(c.getValue(), "UTF-8");
            }
        }
        String bar = param;
        String fileName = BASE_DIR + bar;
~>        java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File(fileName));

        String theme = request.getHeader("X-Theme");
~>        FileReader reader = new FileReader(THEMES + theme + ".css");
    }

    private static final String BASE_DIR = "/srv/docs/";
    private static final String THEMES = "/srv/themes/";
}
