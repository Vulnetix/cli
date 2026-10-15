package com.acme.data;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class TenantDao {
    private final JdbcTemplate jdbc;

    public TenantDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> members(String tenant) {
        String sql = """
                SELECT u.id, u.email
                  FROM users u
                 WHERE u.tenant = '%s'
                """.formatted(tenant);
~>        return jdbc.queryForList(sql);
    }

    public List<Map<String, Object>> active() {
        String sql = """
                SELECT id FROM users WHERE active = true
                """;
        return jdbc.queryForList(sql);
    }
}
