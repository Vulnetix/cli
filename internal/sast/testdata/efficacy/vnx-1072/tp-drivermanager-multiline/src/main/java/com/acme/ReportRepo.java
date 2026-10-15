package com.acme;

import java.sql.*;

public class ReportRepo {
    public int count() throws SQLException {
        Connection conn =
~>            DriverManager.getConnection(
                "jdbc:mysql://localhost/reports", props());
        try (Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery("select count(*) from report");
            rs.next();
            return rs.getInt(1);
        }
    }
}
