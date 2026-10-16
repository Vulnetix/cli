package dao;

import java.sql.*;

public class ProductDao {
    public ResultSet search(Connection c, String term) throws SQLException {
~>        String sql = "SELECT name FROM products WHERE name LIKE '%" + term + "%'";
        return c.createStatement().executeQuery(sql);
    }

    public ResultSet bound(Connection c, String q) throws SQLException {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM products WHERE name LIKE ?");
~>        ps.setString(1, "%" + q + "%");
        return ps.executeQuery();
    }
}
