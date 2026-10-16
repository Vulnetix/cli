package com.acme.web;

public class LookupServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        com.acme.support.RequestFacade facade =
                new com.acme.support.RequestFacade(request);
        String param = facade.fixed("who");
        String bar = "";
        if (param != null) {
            bar =
                    new String(
                            Codec.decode(
                                    Codec.encode(
                                            param.getBytes())));
        }
        String sql = "SELECT * FROM users WHERE name='" + bar + "'";
        java.sql.Statement statement = connection.createStatement();
        statement.execute(sql);
    }
}
