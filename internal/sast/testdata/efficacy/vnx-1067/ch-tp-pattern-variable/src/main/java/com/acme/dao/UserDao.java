package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class UserDao {
    public void search(Connection c, String term) throws Exception {
        String pattern = "%" + term.trim() + "%";
        PreparedStatement ps = c.prepareStatement("SELECT id FROM users WHERE name LIKE ?");
~>        ps.setString(1, pattern);
        ps.executeQuery();
    }
}
