package com.acme.web;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TraceServlet extends HttpServlet {
    private static final Set<String> LANGS = Set.of("en", "fr", "de");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("X-Request-Id", UUID.randomUUID().toString());
        String lang = request.getParameter("lang");
        if (lang == null || !LANGS.contains(lang)) {
            lang = "en";
        }
        response.setHeader("Content-Language", lang);
    }
}
