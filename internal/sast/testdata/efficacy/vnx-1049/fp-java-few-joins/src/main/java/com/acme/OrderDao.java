package com.acme;

public class OrderDao {
    private static final String BY_ID =
        "SELECT o.id, c.name " +
        "FROM orders o " +
        "JOIN customers c ON c.id = o.customer_id " +
        "WHERE o.id = ?";

    private static final String LINES =
        "SELECT l.* FROM lines l JOIN products p ON p.id = l.product_id WHERE l.order_id = ?";

    private static final String TOTALS =
        "SELECT SUM(l.qty) FROM lines l JOIN orders o ON o.id = l.order_id " +
        "JOIN customers c ON c.id = o.customer_id WHERE c.id = ?";
}
