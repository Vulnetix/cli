package com.acme.web;

public class EchoServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("msg");
        if (param == null) param = "";
        String a = param;
        StringBuilder b = new StringBuilder(a);
        b.append(" tail");
        java.util.HashMap<String, Object> store = new java.util.HashMap<String, Object>();
        store.put("k", b.toString());
        String c = (String) store.get("k");
        String d = c.substring(0, c.length() - 1);
        String e =
                new String(
                        Codec.decode(
                                Codec.encode(
                                        d.getBytes())));
        String f = e.split(" ")[0];
        String g = Registry.lookup().apply(f);
        response.setHeader("X-XSS-Protection", "0");
~>        response.getWriter().println(g);
    }
}
