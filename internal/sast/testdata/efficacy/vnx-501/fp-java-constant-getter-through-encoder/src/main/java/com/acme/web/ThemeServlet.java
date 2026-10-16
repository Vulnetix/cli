package com.acme.web;

public class ThemeServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        com.acme.support.RequestFacade facade =
                new com.acme.support.RequestFacade(request);
        String theme = facade.fixed("theme");
        String shaped = shape(request, theme);
        request.getSession().putValue(shaped, "1");
        request.getSession().setAttribute("theme", theme);
    }

    private static String shape(HttpServletRequest request, String value) {
        String out = org.acme.text.Escaper.instance().encode(value);
        return out;
    }
}
