package com.acme.data;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class Totals {
    private Connection conn;

    // Operands appended to the builder come from calls into other classes
    // that are given literals only.
    public ResultSet totals() throws Exception {
        StringBuilder sb = new StringBuilder("SELECT ");
        sb.append(Columns.name("total")).append(" FROM orders");
        Statement st = conn.createStatement();
        return st.executeQuery(sb.toString());
    }

    public ResultSet byRegion() throws Exception {
        Quoter quoter = QuoterFactory.create();
        StringBuilder sb = new StringBuilder("SELECT id FROM orders WHERE region = ");
        sb.append(quoter.quote("eu"));
        Statement st = conn.createStatement();
        return st.executeQuery(sb.toString());
    }
}
