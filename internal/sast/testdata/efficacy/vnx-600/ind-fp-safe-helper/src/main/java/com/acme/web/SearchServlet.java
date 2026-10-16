package com.acme.web;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SearchServlet extends HttpServlet {

    private SearchIndex index;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int page = intParam(req.getParameter("page"), 1);
        int size = intParam(req.getParameter("size"), 20);
        resp.getWriter().write(index.search(req.getParameter("q"), page, size));
    }

    private static int intParam(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
