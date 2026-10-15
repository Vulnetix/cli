package com.shop.web;

import java.io.IOException;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LangServlet extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("en", "fr", "de");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String lang = request.getParameter("lang");
        if (!ALLOWED.contains(lang)) {
            response.sendError(400);
            return;
        }
        request.getSession().setAttribute("lang", lang);
    }
}
