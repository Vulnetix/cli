package com.acme.dao;

import java.sql.*;

public class OrderDao {
    public ResultSet find(Connection c, long customerId, String status) throws SQLException {
        PreparedStatement ps = c.prepareStatement(
            "SELECT * FROM orders WHERE customer_id = ? AND status = ?");
        ps.setLong(1, customerId);
        ps.setString(2, status);
        return ps.executeQuery();
    }
}
