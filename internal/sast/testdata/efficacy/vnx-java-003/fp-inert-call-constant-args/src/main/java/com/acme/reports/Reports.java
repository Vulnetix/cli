package com.acme.reports;

import java.sql.Connection;
import java.sql.Statement;

public class Reports {
    private Connection connection;

    // A helper from another class, called with literals only, on a type name or
    // on a local built from such a call: nothing run-time can reach the text.
    public void orderedByFactoryProduct() throws Exception {
        Quoter quoter = QuoterFactory.create();
        String column = quoter.quote("created_at");
        String sql = "SELECT id FROM orders ORDER BY " + column;
        Statement st = connection.createStatement();
        st.executeQuery(sql);
    }

    public void staticLookup() throws Exception {
        String table = TableNames.forRegion("eu");
        Statement st = connection.createStatement();
        st.executeQuery("SELECT id FROM " + table);
    }

    public void constructedWithConstants() throws Exception {
        Fragment fragment = new Fragment("status", 3);
        String where = fragment.render("open");
        Statement st = connection.createStatement();
        st.executeUpdate("UPDATE orders SET archived = 1 WHERE " + where);
    }

    public void nestedInertCalls() throws Exception {
        Quoter quoter = QuoterFactory.create();
        String column = quoter.quote(Columns.name("total"));
        Statement st = connection.createStatement();
        st.executeQuery("SELECT " + column + " FROM orders");
    }
}
