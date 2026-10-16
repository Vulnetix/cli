package com.acme.web;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProfileServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        String agent = request.getHeader("User-Agent");
        out.println("<html><body>");
~>        out.println("Browser: " + agent);
        String theme = "light";
        for (Cookie c : request.getCookies()) {
            if (c.getName().equals("theme")) {
                theme = c.getValue();
            }
        }
~>        out.print("<body class='" + theme + "'>");
        out.println("</body></html>");
    }

    protected void show(HttpServletRequest request, HttpServletResponse response, PrintWriter w) throws IOException {
        String path = request.getPathInfo();
~>        w.write("<a href='" + path + "'>back</a>");
    }
}
