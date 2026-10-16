package com.acme.web;

public class BannerServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = "welcome";
        String a = param;
        StringBuilder b = new StringBuilder(a);
        b.append(" tail");
        String c = b.toString();
        String d = c.substring(0, c.length() - 1);
        String e = d.trim();
        String f = e.split(" ")[0];
        String g = f.toUpperCase();
        response.getWriter().println(g);
    }
}
