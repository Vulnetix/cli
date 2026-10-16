package com.acme.data;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

public class AuditRepository {
    private final JdbcTemplate jdbcTemplate;

    public AuditRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> byActor(String actor) {
        return jdbcTemplate.queryForList("select * from audit where actor = '" + actor + "'");
    }

    public int purge(String days) {
        return jdbcTemplate.update("DELETE FROM audit WHERE created < now() - interval '" + days + " days'");
    }

    public List<Map<String, Object>> sorted(String column) {
        String sql = "SELECT * FROM audit ORDER BY " + column;
        return jdbcTemplate.queryForList(sql);
    }
}
