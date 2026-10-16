package com.acme.web;

public class ViewServlet extends javax.servlet.http.HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String queryString = request.getQueryString();
        int at = queryString.indexOf("view=");
        String view =
                queryString.substring(
                        at + 5);
        String shown = java.net.URLDecoder.decode(view, "UTF-8");
~>        request.getSession().setAttribute("view", shown);
    }
}
