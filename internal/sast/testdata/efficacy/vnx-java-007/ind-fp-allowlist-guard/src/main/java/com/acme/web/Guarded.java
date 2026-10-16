package com.acme.web;

import java.io.IOException;
import java.util.Map;
import javax.servlet.http.*;

public class Guarded {
    private static final Map<String, String> DEST = Map.of("home", "/home", "docs", "/docs");

    void a(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String key = req.getParameter("to");
        resp.sendRedirect(DEST.getOrDefault(key, "/home"));
    }

    void b(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String next = req.getParameter("next");
        if (next == null || !next.startsWith("/") || next.startsWith("//")) {
            next = "/";
        }
        resp.sendRedirect(next);
    }
}
