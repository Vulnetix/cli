package com.acme.repo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;

public class OrderDao {
    private final JdbcTemplate jdbcTemplate;
    OrderDao(JdbcTemplate t) { this.jdbcTemplate = t; }

    List<String> byStatus(String status) {
        StringBuffer buf = new StringBuffer();
        buf.append("SELECT id FROM orders WHERE status = ");
        buf.append(status);
~>        return jdbcTemplate.queryForList(buf.toString(), String.class);
    }
}
