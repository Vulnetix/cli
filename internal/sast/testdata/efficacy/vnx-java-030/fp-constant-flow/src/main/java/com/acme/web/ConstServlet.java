package com.acme.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ConstServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        String param = request.getParameter("q");
        String bar;
        int limit = 86;
        if (limit * 2 > 100) {
            bar = "static page";
        } else {
            bar = param;
        }
        response.getWriter().println("<p>" + bar + "</p>");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        List<String> items = new ArrayList<String>();
        items.add("first");
        items.add(request.getParameter("q"));
        String shown = items.get(0);
        response.getWriter().println("<li>" + shown + "</li>");

        Map<String, String> m = new HashMap<String, String>();
        m.put("a", "alpha");
        m.put("b", request.getHeader("X-B"));
        String label = m.get("a");
        response.getWriter().println(label);
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        String ignored = request.getParameter("q");
        String msg = "Saved";
        response.getWriter().println(msg);
    }
}
