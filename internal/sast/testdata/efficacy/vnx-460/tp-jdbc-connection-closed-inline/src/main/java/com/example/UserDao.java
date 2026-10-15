package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDao {
    public int count(String url) throws SQLException {
~>        Connection conn = DriverManager.getConnection(url);
~>        PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM users");
        ResultSet rs = ps.executeQuery();
        rs.next();
        int n = rs.getInt(1);
        ps.close();
        conn.close();
        return n;
    }
}
