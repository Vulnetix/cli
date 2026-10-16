package com.acme.data;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class Search {
    private Connection conn;

    // The same operand shapes with a run-time value in the way.
    public ResultSet argumentIsRuntimeValue(String column) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT ");
        sb.append(Columns.name(column)).append(" FROM orders");
        Statement st = conn.createStatement();
~>        return st.executeQuery(sb.toString());
    }

    public ResultSet sourceLikeName() throws Exception {
        StringBuilder sb = new StringBuilder("SELECT id FROM orders WHERE region = ");
        sb.append(Prompts.readLine("region"));
        Statement st = conn.createStatement();
~>        return st.executeQuery(sb.toString());
    }

    public ResultSet receiverFedRuntimeValue(String region) throws Exception {
        Quoter quoter = QuoterFactory.create();
        quoter.setStyle(region);
        StringBuilder sb = new StringBuilder("SELECT id FROM orders WHERE region = ");
        sb.append(quoter.quote("eu"));
        Statement st = conn.createStatement();
~>        return st.executeQuery(sb.toString());
    }
}
