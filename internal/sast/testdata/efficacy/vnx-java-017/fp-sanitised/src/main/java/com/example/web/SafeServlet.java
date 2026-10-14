package com.example.web;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class SafeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String lang = request.getParameter("lang");
        lang = lang.replaceAll("[\\r\\n]", "");
        response.setHeader("Content-Language", lang);

        String name = request.getParameter("name");
        response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(name, StandardCharsets.UTF_8));

        String echo = Encode.forUriComponent(request.getHeader("X-Echo"));
        response.addHeader("X-Echo", echo);

        String page = request.getParameter("page");
        int n = Integer.parseInt(page);
        response.setHeader("X-Page", String.valueOf(n));

        String next = request.getParameter("next");
        if (!next.matches("^/[A-Za-z0-9/_-]*$")) {
            next = "/";
        }
        response.sendRedirect(next);
    }
}
