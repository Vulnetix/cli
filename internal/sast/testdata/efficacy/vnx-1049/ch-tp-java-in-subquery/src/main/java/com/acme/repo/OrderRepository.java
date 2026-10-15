package com.acme.repo;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class OrderRepository {
    private static final String STALE_ORDERS =
~>        "SELECT o.id, c.name FROM orders o "
            + "JOIN customers c ON c.id = o.customer_id "
            + "JOIN shipments s ON s.order_id = o.id "
            + "WHERE o.id IN (SELECT order_id FROM order_items WHERE qty > 10) "
            + "AND c.id NOT IN (SELECT customer_id FROM blocked) "
            + "AND s.carrier_id IN (SELECT id FROM carriers WHERE active = 0)";

    public PreparedStatement stale(Connection conn) throws Exception {
        return conn.prepareStatement(STALE_ORDERS);
    }
}
