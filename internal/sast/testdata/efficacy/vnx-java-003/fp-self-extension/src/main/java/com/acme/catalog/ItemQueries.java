package com.acme.catalog;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class ItemQueries {
    private final JdbcTemplate jdbcTemplate;

    public ItemQueries(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> list(boolean inStock, String category) {
        String sql = "SELECT id, title FROM items WHERE category = ?";
        if (inStock) {
            sql += " AND qty > 0";
        }
        sql = sql + " ORDER BY title";
        return jdbcTemplate.queryForList(sql, category);
    }

    public List<Map<String, Object>> page(int limit) {
        String query = "SELECT id FROM items";
        query = query + " LIMIT ?";
        return jdbcTemplate.queryForList(query, limit);
    }
}
