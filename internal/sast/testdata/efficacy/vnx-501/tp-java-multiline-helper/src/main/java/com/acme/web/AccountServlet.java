package com.acme.web;

public class AccountServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String raw = request.getParameter("id");
        String id = clean(request, raw);
~>        request.getSession().putValue("id", id);
    }

    private static String clean(HttpServletRequest request, String value) {
        String out = "";
        if (value != null) {
            out =
                    new String(
                            Codec.decode(
                                    Codec.encode(value.getBytes())));
        }
        return out;
    }
}
