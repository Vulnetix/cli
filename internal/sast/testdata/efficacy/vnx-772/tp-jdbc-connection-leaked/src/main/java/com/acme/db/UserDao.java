package com.acme.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserDao {
    private final String url;

    public UserDao(String url) { this.url = url; }

    public boolean exists(String name) throws Exception {
~>        Connection conn = DriverManager.getConnection(url);
        PreparedStatement ps = conn.prepareStatement("select 1 from users where name = ?");
        ps.setString(1, name);
        ResultSet rs = ps.executeQuery();
        return rs.next();
    }
}
