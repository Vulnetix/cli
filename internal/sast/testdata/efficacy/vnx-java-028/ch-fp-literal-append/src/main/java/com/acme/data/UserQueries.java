package com.acme.data;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;

public class UserQueries {
    private final JdbcTemplate jdbcTemplate;

    public UserQueries(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<User> list(boolean activeOnly, String name) {
        String sql = "SELECT id, name FROM users WHERE name = ?";
        if (activeOnly) {
            sql += " AND active = 1";
        }
        sql = sql + " ORDER BY name";
        return jdbcTemplate.query(sql, new UserRowMapper(), name);
    }
}
