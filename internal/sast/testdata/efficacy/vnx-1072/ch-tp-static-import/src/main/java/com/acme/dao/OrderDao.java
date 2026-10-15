package com.acme.dao;

import static java.sql.DriverManager.getConnection;

import java.sql.Connection;
import java.sql.SQLException;

public class OrderDao {
    private final String url;

    public OrderDao(String url) {
        this.url = url;
    }

    public int count() throws SQLException {
~>        try (Connection c = getConnection(url, "app", System.getenv("DB_PASSWORD"))) {
            return c.createStatement().executeQuery("select count(*) from orders").getInt(1);
        }
    }
}
