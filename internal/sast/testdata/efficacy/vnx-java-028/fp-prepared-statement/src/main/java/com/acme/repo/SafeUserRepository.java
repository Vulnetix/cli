package com.acme.repo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class SafeUserRepository {
    private final Connection conn;
    private final JdbcTemplate jdbcTemplate;

    public SafeUserRepository(Connection conn, JdbcTemplate t) { this.conn = conn; this.jdbcTemplate = t; }

    public ResultSet byName(String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, name);
        return ps.executeQuery();
    }

    public List<Map<String, Object>> byRegion(String region) {
        return jdbcTemplate.queryForList("SELECT * FROM sales WHERE region = ?", region);
    }

    public int bump(String sku) {
        return jdbcTemplate.update("UPDATE stock SET qty = qty + 1 WHERE sku = ?", sku);
    }

    public void insert(String name, int age) throws Exception {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO users (name, age) VALUES (?, ?)")) {
            ps.setString(1, name);
            ps.setInt(2, age);
            ps.executeUpdate();
        }
    }
}
