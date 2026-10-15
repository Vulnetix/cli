package com.acme;

import java.sql.*;

public class UserDao {
    public int countUsers(String url) throws SQLException {
~>        Connection conn = DriverManager.getConnection(url, "app", System.getenv("DB_PASS"));
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM users");
        rs.next();
        return rs.getInt(1);
    }
}
