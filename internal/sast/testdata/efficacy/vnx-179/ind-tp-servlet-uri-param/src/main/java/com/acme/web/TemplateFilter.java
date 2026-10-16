package com.acme.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TemplateFilter {

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException {
        var query = request.getQueryString();
~>        if (query != null && (query.contains("..") || query.contains("<script"))) {
            response.sendError(400);
            return;
        }
        var template = request.getParameter("template");
        render(template, response);
    }

    private void render(String template, HttpServletResponse response) throws IOException {
        response.getWriter().write(Templates.load(template));
    }
}
