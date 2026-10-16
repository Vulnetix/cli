package com.acme.reports;

import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Search {
    private Connection connection;

    // The same helper shapes as the constant case, each with one request
    // value in the way: all stay reported.
    public void helperReceivesRequestValue(HttpServletRequest request) throws Exception {
        String param = request.getParameter("col");
        Quoter quoter = QuoterFactory.create();
        String column = quoter.quote(param);
        Statement st = connection.createStatement();
~>        st.executeQuery("SELECT id FROM orders ORDER BY " + column);
    }

    public void receiverBuiltFromRequest(HttpServletRequest request) throws Exception {
        Quoter quoter = new Quoter(request.getParameter("style"));
        String column = quoter.quote("created_at");
        Statement st = connection.createStatement();
~>        st.executeQuery("SELECT id FROM orders ORDER BY " + column);
    }

    public void sourceLikeMethodName() throws Exception {
        String table = Prompts.readLine("table");
        Statement st = connection.createStatement();
~>        st.executeQuery("SELECT id FROM " + table);
    }

    public void receiverFedARequestValue(HttpServletRequest request) throws Exception {
        Fragment fragment = new Fragment("status", 3);
        fragment.add(request.getParameter("w"));
        String where = fragment.render("open");
        Statement st = connection.createStatement();
~>        st.executeUpdate("UPDATE orders SET archived = 1 WHERE " + where);
    }

    public void receiverIsARequestValue(HttpServletRequest request) throws Exception {
        String name = request.getParameter("n");
        String column = name.toLowerCase();
        Statement st = connection.createStatement();
~>        st.executeQuery("SELECT " + column + " FROM orders");
    }
}
