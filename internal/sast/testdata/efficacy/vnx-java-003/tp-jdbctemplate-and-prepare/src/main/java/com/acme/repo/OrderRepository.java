package com.acme.repo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class OrderRepository {
    private final JdbcTemplate jdbcTemplate;

    public OrderRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> byCustomer(String customer, Connection conn) throws Exception {
~>        jdbcTemplate.update("UPDATE orders SET viewed = 1 WHERE customer = '" + customer + "'");
        String sort = "ORDER BY " + customer;
~>        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders " + sort);
~>        return jdbcTemplate.queryForList(
                "SELECT * FROM orders WHERE customer = '" + customer + "'");
    }
}
