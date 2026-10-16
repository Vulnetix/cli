package com.acme.web;

public class PingServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        com.acme.support.RequestFacade facade =
                new com.acme.support.RequestFacade(request);
        String param = facade.fixed("host");
        String bar = "";
        if (param != null) {
            bar =
                    new String(
                            Codec.decode(
                                    Codec.encode(
                                            param.getBytes())));
        }
        String[] args = new String[] {"sh", "-c", "ping -c1 " + bar};
        Process p = Runtime.getRuntime().exec(args);
    }
}
