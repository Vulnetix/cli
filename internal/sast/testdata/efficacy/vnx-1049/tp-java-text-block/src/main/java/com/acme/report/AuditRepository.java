package com.acme.report;

import org.springframework.jdbc.core.JdbcTemplate;

public class AuditRepository {
    private final JdbcTemplate jdbc;

    public AuditRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public int count() {
~>        String sql = """
            SELECT COUNT(*)
            FROM audit a
            JOIN users u ON u.id = a.user_id
            JOIN roles r ON r.id = u.role_id
            JOIN tenants t ON t.id = u.tenant_id
            WHERE a.user_id IN (SELECT id FROM users WHERE disabled = false)
              AND t.id NOT IN (SELECT tenant_id FROM suspended)
            """;
        return jdbc.queryForObject(sql, Integer.class);
    }
}
