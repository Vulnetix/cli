package com.acme.repo;

import java.sql.*;

public class ProductDao {
    List<String> search(Connection c, String term) throws SQLException {
~>        String sql = "SELECT name FROM products WHERE name LIKE '%" + term + "%'";
~>        try (PreparedStatement ps = c.prepareStatement("SELECT id FROM tags WHERE label like '%sale'")) {
            ps.executeQuery();
        }
        return null;
    }
}
