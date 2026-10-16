package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

public class MixedServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String name = request.getParameter("name");
        if (request.getParameter("raw") == null) {
            name = HtmlUtils.htmlEscape(name);
        }
~>        response.getWriter().println("<p>" + name + "</p>");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String title = decorate(request.getParameter("title"));
~>        response.getWriter().println(title);
        String escaped = HtmlUtils.htmlEscape(request.getParameter("other"));
        response.getWriter().println(escaped);
    }

    private static String decorate(String value) {
        return "<h2>" + value + "</h2>";
    }
}
