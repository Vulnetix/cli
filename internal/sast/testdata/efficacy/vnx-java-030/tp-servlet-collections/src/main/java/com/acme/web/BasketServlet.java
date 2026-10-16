package com.acme.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BasketServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        List<String> items = new ArrayList<String>();
        items.add("bread");
        items.add(request.getParameter("extra"));
        items.add("milk");
        String last = items.get(1);
~>        response.getWriter().println("<li>" + last + "</li>");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        Map<String, String> labels = new HashMap<String, String>();
        labels.put("fixed", "Basket");
        labels.put("custom", request.getHeader("X-Label"));
        String title = labels.get("custom");
~>        response.getWriter().print(title);
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        String[] values = request.getParameterValues("tag");
        String tag = values != null && values.length > 0 ? values[0] : "";
        StringBuilder html = new StringBuilder("<span>");
        html.append(tag);
        html.append("</span>");
~>        response.getWriter().write(html.toString());
    }
}
