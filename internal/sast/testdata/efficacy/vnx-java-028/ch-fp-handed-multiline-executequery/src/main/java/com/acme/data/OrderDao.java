package com.acme.data;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class OrderDao {
    private final Connection connection;

    public OrderDao(Connection connection) {
        this.connection = connection;
    }

    public ResultSet recentOrders(String customerId) throws SQLException {
        Statement statement = connection.createStatement();
        return statement.executeQuery(
                "SELECT id, total FROM orders WHERE customer_id = " + customerId
                + " ORDER BY created_at DESC");
    }

    public ResultSet byName(String name) throws SQLException {
        return connection.createStatement().executeQuery("select * from users where name = '" + name + "'");
    }

    public void prepare(String id) throws SQLException {
        connection.prepareStatement("DELETE FROM carts WHERE id = " + id).executeUpdate();
    }
}
