package com.acme;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserStats {
    private final String url;
    private final String password;

    public UserStats(String url, String password) {
        this.url = url;
        this.password = password;
    }

    public long countActive() throws SQLException {
~>        Connection conn = DriverManager.getConnection(url, "reporting", password);
        ResultSet rs = conn.createStatement()
                .executeQuery("SELECT COUNT(*) FROM users WHERE active = true");
        rs.next();
        return rs.getLong(1);
    }
}
