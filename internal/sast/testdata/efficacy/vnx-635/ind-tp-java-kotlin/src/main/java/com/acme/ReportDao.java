package com.acme;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ReportDao {
    private final Connection conn;

    public ReportDao(Connection conn) {
        this.conn = conn;
    }

    public ResultSet byName(String name) throws SQLException {
~>        // TODO: this is vulnerable to SQL injection, switch to PreparedStatement
        return conn.createStatement().executeQuery("SELECT * FROM r WHERE n='" + name + "'");
    }
}
