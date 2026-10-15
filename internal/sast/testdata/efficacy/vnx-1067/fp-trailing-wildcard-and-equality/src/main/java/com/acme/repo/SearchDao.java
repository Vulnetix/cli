package com.acme.repo;

import java.sql.*;

public class SearchDao {
    ResultSet prefix(Connection c, String q) throws SQLException {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE email LIKE ? AND id = ?");
        ps.setString(1, q + "%");
        Statement s = c.createStatement();
        s.executeQuery("SELECT * FROM users WHERE name LIKE 'adm%'");
        s.executeQuery("SELECT COUNT(*) FROM users WHERE lower_name = ?");
        return ps.executeQuery();
    }
}
