package com.acme.web;

public class ProfileServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        com.acme.support.RequestFacade facade =
                new com.acme.support.RequestFacade(request);
        String raw = facade.param("nick");
        String a = raw;
        StringBuilder b = new StringBuilder(a);
        b.append("-x");
        java.util.Map<String, Object> m = new java.util.HashMap<String, Object>();
        m.put("k", b.toString());
        String c = (String) m.get("k");
        String d = c.substring(1);
        String e =
                new String(
                        Codec.decode(
                                Codec.encode(d.getBytes())));
        String f = e.split(" ")[0];
        String nick = f.trim();
~>        request.getSession().setAttribute("nick", nick);
    }
}
